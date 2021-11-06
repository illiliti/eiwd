/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef HAVE_EXPLICIT_BZERO
static inline void explicit_bzero(void *s, size_t n)
{
        memset(s, 0, n);
        __asm__ __volatile__ ("" : : "r"(s) : "memory");
}
#endif

#ifndef HAVE_RAWMEMCHR
static inline void *rawmemchr(const void *s, int c)
{
_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wstringop-overflow=\"")
	return memchr(s, c, (size_t) -1);
_Pragma("GCC diagnostic pop")
}
#endif

#ifndef HAVE_REALLOCARRAY
static inline void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	return realloc(ptr, nmemb * size);
}
#endif
