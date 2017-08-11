/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*  Mini-parser code mostly borrowed from Dynamips. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>

#include "hypervisor_parser.h"

#define TOKEN_MAX_SIZE  512

/* Character types */
enum {
   PARSER_CHAR_BLANK,
   PARSER_CHAR_NEWLINE,
   PARSER_CHAR_COMMENT,
   PARSER_CHAR_QUOTE,
   PARSER_CHAR_OTHER,
};

/* Get a description given an error code */
char *parser_strerror(parser_context_t *ctx)
{
   printf("error = %d\n",ctx->error);

   switch(ctx->error) {
      case 0:
         return "no error";
      case PARSER_ERROR_NOMEM:
         return "insufficient memory";
      case PARSER_ERROR_UNEXP_QUOTE:
         return "unexpected quote";
      case PARSER_ERROR_UNEXP_EOL:
         return "unexpected end of line";
      default:
         return "unknown error";
   }
}

/* Dump a token list */
void parser_dump_tokens(parser_context_t *ctx)
{
   parser_token_t *tok;

   for(tok=ctx->tok_head;tok;tok=tok->next)
      printf("\"%s\" ",tok->value);
}

/* Map a token list to an array */
char **parser_map_array(parser_context_t *ctx)
{
   parser_token_t *tok;
   char **map;
   int i;

   if (ctx->tok_count <= 0)
      return NULL;

   if (!(map = calloc(ctx->tok_count,sizeof(char **))))
      return NULL;

   for(i=0,tok=ctx->tok_head;(i<ctx->tok_count) && tok;i++,tok=tok->next)
      map[i] = tok->value;

   return map;
}

/* Add a character to temporary token (resize if necessary) */
static int tmp_token_add_char(parser_context_t *ctx,char c)
{
   int new_size;
   char *new_str;

   if (!ctx->tmp_tok || (ctx->tmp_cur_len == (ctx->tmp_tot_len - 1))) {
      new_size = ctx->tmp_tot_len + TOKEN_MAX_SIZE;
      new_str  = realloc(ctx->tmp_tok,new_size);
	  
	  if (!new_str)
         return(-1);

      ctx->tmp_tok = new_str;
      ctx->tmp_tot_len = new_size;
   }

   ctx->tmp_tok[ctx->tmp_cur_len++] = c;
   ctx->tmp_tok[ctx->tmp_cur_len] = 0;
   return(0);
}

/* Move current token to the active token list */
static int parser_move_tmp_token(parser_context_t *ctx)
{
   parser_token_t *tok;

   /* no token ... */
   if (!ctx->tmp_tok)
      return(0);

   if (!(tok = malloc(sizeof(*tok))))
      return(-1);

   tok->value = ctx->tmp_tok;
   tok->next  = NULL;

   /* add it to the token list */
   if (ctx->tok_last != NULL)
      ctx->tok_last->next = tok;
   else
      ctx->tok_head = tok;

   ctx->tok_last = tok;
   ctx->tok_count++;

   /* start a new token */
   ctx->tmp_tok = NULL;
   ctx->tmp_tot_len = ctx->tmp_cur_len = 0;
   return(0);
}

/* Initialize parser context */
void parser_context_init(parser_context_t *ctx)
{
   ctx->tok_head = ctx->tok_last = NULL;
   ctx->tok_count = 0;

   ctx->tmp_tok = NULL;
   ctx->tmp_tot_len = ctx->tmp_cur_len = 0;

   ctx->state = PARSER_STATE_BLANK;
   ctx->error = 0;

   ctx->consumed_len = 0;
}

/* Free a token list */
void parser_free_tokens(parser_token_t *tok_list)
{
   parser_token_t *t,*next;

   for(t=tok_list;t;t=next) {
      next = t->next;
      free(t->value);
      free(t);
   }
}

/* Free memory used by a parser context */
void parser_context_free(parser_context_t *ctx)
{
   parser_free_tokens(ctx->tok_head);

   if (ctx->tmp_tok != NULL)
      free(ctx->tmp_tok);

   parser_context_init(ctx);
}

/* Determine the type of the input character */
static int parser_get_char_type(unsigned char c)
{
   switch(c) {
      case '\n':
      case '\r':
      case 0:
         return(PARSER_CHAR_NEWLINE);
      case '\t':
         //case '\r':
      case ' ':
         return(PARSER_CHAR_BLANK);
      case '!':
      case '#':
         return(PARSER_CHAR_COMMENT);
      case '"':
         return(PARSER_CHAR_QUOTE);
      default:
         return(PARSER_CHAR_OTHER);
   }
}

/* Send a buffer to the tokenizer */
int parser_scan_buffer(parser_context_t *ctx,char *buf,int buf_size)
{
   int i,type;
   unsigned char c;

   for(i=0;(i<buf_size) && (ctx->state != PARSER_STATE_DONE);i++)
   {
      ctx->consumed_len++;
      c = buf[i];

      /* Determine character type */
      type = parser_get_char_type(c);

      /* Basic finite state machine */
      switch(ctx->state) {
         case PARSER_STATE_SKIP:
            if (type == PARSER_CHAR_NEWLINE)
               ctx->state = PARSER_STATE_DONE;

            /* Simply ignore character until we reach end of line */
            break;

         case PARSER_STATE_BLANK:
            switch(type) {
               case PARSER_CHAR_BLANK:
                  /* Eat space */
                  break;

               case PARSER_CHAR_COMMENT:
                  ctx->state = PARSER_STATE_SKIP;
                  break;

               case PARSER_CHAR_NEWLINE:
                  ctx->state = PARSER_STATE_DONE;
                  break;

               case PARSER_CHAR_QUOTE:
                  ctx->state = PARSER_STATE_QUOTED_STRING;
                  break;

               default:
                  /* Begin a new string */
                  if (!tmp_token_add_char(ctx,c)) {
                     ctx->state = PARSER_STATE_STRING;
                  } else {
                     ctx->state = PARSER_STATE_SKIP;
                     ctx->error = PARSER_ERROR_NOMEM;
                  }
            }
            break;

         case PARSER_STATE_STRING:
            switch(type) {
               case PARSER_CHAR_BLANK:
                  if (!parser_move_tmp_token(ctx)) {
                     ctx->state = PARSER_STATE_BLANK;
                  } else {
                     ctx->state = PARSER_STATE_SKIP;
                     ctx->error = PARSER_ERROR_NOMEM;
                  }
                  break;

               case PARSER_CHAR_NEWLINE:
                  if (parser_move_tmp_token(ctx) == -1)
                     ctx->error = PARSER_ERROR_NOMEM;

                  ctx->state = PARSER_STATE_DONE;
                  break;

               case PARSER_CHAR_COMMENT:
                  if (parser_move_tmp_token(ctx) == -1)
                     ctx->error = PARSER_ERROR_NOMEM;

                  ctx->state = PARSER_STATE_SKIP;
                  break;

               case PARSER_CHAR_QUOTE:
                  ctx->error = PARSER_ERROR_UNEXP_QUOTE;
                  ctx->state = PARSER_STATE_SKIP;
                  break;

               default:
                  /* Add the character to the buffer */
                  if (tmp_token_add_char(ctx,c) == -1) {
                     ctx->state = PARSER_STATE_SKIP;
                     ctx->error = PARSER_ERROR_NOMEM;
                  }
            }
            break;

         case PARSER_STATE_QUOTED_STRING:
            switch(type) {
               case PARSER_CHAR_NEWLINE:
                  /* Unterminated string! */
                  ctx->error = PARSER_ERROR_UNEXP_EOL;
                  ctx->state = PARSER_STATE_DONE;
                  break;

               case PARSER_CHAR_QUOTE:
                  if (!parser_move_tmp_token(ctx)) {
                     ctx->state = PARSER_STATE_BLANK;
                  } else {
                     ctx->state = PARSER_STATE_SKIP;
                     ctx->error = PARSER_ERROR_NOMEM;
                  }
                  break;

               default:
                  /* Add the character to the buffer */
                  if (tmp_token_add_char(ctx,c) == -1) {
                     ctx->state = PARSER_STATE_SKIP;
                     ctx->error = PARSER_ERROR_NOMEM;
                  }
            }
            break;
      }
   }

   return(ctx->state == PARSER_STATE_DONE);
}
