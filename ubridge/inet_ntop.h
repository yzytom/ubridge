#include <windows.h>
#include <stdio.h>
#define IN6ADDRSZ 16
#define INT16SZ 2
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
static const char *inet_ntop_v4(const void *src, char *dst, size_t size);
static const char *inet_ntop_v6(const u_char *src, char *dst, size_t size);
const char *inet_ntop_xp(int af, const void *src, char *dst, size_t size);
const char *inet_ntop_xp(int af, const void *src, char *dst, size_t size)
{
	switch (af) {
	case AF_INET:
		return inet_ntop_v4(src, dst, size);
#ifdef INET6
	case AF_INET6:
		return inet_ntop_v6((const u_char*)src, dst, size);
#endif
	default:
		errno = EAFNOSUPPORT;
		return NULL;
	}
}


static const char *inet_ntop_v4(const void *src, char *dst, size_t size)
{
	const char digits[] = "0123456789";
	struct in_addr *addr = (struct in_addr *)src;
	u_long a = ntohl(addr->s_addr);
	const char *orig_dst = dst;

	if (size < INET_ADDRSTRLEN) {
		errno = ENOSPC;
		return NULL;
	}
	for (int i = 0; i < 4; ++i) {
		int n = (a >> (24 - i * 8)) & 0xFF;
		int non_zerop = 0;

		if (non_zerop || n / 100 > 0) {
			*dst++ = digits[n / 100];
			n %= 100;
			non_zerop = 1;
		}
		if (non_zerop || n / 10 > 0) {
			*dst++ = digits[n / 10];
			n %= 10;
			non_zerop = 1;
		}
		*dst++ = digits[n];
		if (i != 3)
			*dst++ = '.';
	}
	*dst++ = '\0';
	return orig_dst;
}



/*
* Convert IPv6 binary address into presentation (printable) format.
*/
static const char *inet_ntop_v6(const u_char *src, char *dst, size_t size)
{
	/*
	* Note that int32_t and int16_t need only be "at least" large enough
	* to contain a value of the specified size.  On some systems, like
	* Crays, there is no such thing as an integer variable with 16 bits.
	* Keep this in mind if you think this function should have been coded
	* to use pointer overlays.  All the world's not a VAX.
	*/
	char  tmp[INET6_ADDRSTRLEN + 1];
	char *tp;
	struct {
		long base;
		long len;
	} best, cur;
	u_long words[IN6ADDRSZ / INT16SZ];
	int    i;

	/* Preprocess:
	*  Copy the input (bytewise) array into a wordwise array.
	*  Find the longest run of 0x00's in src[] for :: shorthanding.
	*/
	memset(words, 0, sizeof(words));
	for (i = 0; i < IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));

	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
	{
		if (words[i] == 0)
		{
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else cur.len++;
		}
		else if (cur.base != -1)
		{
			if (best.base == -1 || cur.len > best.len)
				best = cur;
			cur.base = -1;
		}
	}
	if ((cur.base != -1) && (best.base == -1 || cur.len > best.len))
		best = cur;
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/* Format the result.
	*/
	tp = tmp;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
	{
		/* Are we inside the best run of 0x00's?
		*/
		if (best.base != -1 && i >= best.base && i < (best.base + best.len))
		{
			if (i == best.base)
				*tp++ = ':';
			continue;
		}

		/* Are we following an initial run of 0x00s or any real hex?
		*/
		if (i != 0)
			*tp++ = ':';

		/* Is this address an encapsulated IPv4?
		*/
		if (i == 6 && best.base == 0 &&
			(best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
		{
			if (!inet_ntop_v4(src + 12, tp, sizeof(tmp) - (tp - tmp)))
			{
				errno = ENOSPC;
				return (NULL);
			}
			tp += strlen(tp);
			break;
		}
		tp += sprintf(tp, "%lX", words[i]);
	}

	/* Was it a trailing run of 0x00's?
	*/
	if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/* Check for overflow, copy, and we're done.
	*/
	if ((size_t)(tp - tmp) > size)
	{
		errno = ENOSPC;
		return (NULL);
	}
	return strcpy(dst, tmp);
	return (NULL);
}