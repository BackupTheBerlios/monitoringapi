#include <stdio.h>
#include <stdlib.h>

#include <mstring.h>

/****************************************************************
 *
 *  Function: contains_substring(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      b_len => data buffer length
 *      pat => pattern to find
 *      p_len => length of the data in the pattern buffer
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/

int contains_substring(char *buf, int b_len, char *pat, int p_len)
{
	char *b_idx;					 /* index ptr into the data buffer */
	char *p_idx;					 /* index ptr into the pattern buffer */
	char *b_end;					 /* ptr to the end of the data buffer */
	int m_cnt = 0;					 /* number of pattern matches so far... */

	/*
	 * mark the end of the strs 
	 */
	b_end = (char *)(buf + b_len);

	/*
	 * init the index ptrs 
	 */
	b_idx = buf;
	p_idx = pat;

	do
	{
		if(*p_idx == *b_idx)
		{
			if(m_cnt == (p_len - 1))
			{
				return 1;
			}

			m_cnt++;
			b_idx++;
			p_idx++;
		}
		else
		{
			if(m_cnt == 0)
			{
				b_idx++;
			}
			else
			{
				b_idx = b_idx - (m_cnt - 1);
			}

			p_idx = pat;

			m_cnt = 0;
		}

	}
	while(b_idx < b_end);


	/*
	 * if we make it here we didn't find what we were looking for 
	 */
	return 0;
}




/****************************************************************
 *
 *  Function: make_skip(char *, int)
 *
 *  Purpose: Create a Boyer-Moore skip table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the skip table
 *
 ****************************************************************/
int *make_skip(char *ptrn, int plen)
{
	int *skip = (int *)malloc(256 * sizeof(int));
	int *sptr = &skip[256];

	if(skip == NULL)
	{
		return NULL;
	}

	while(sptr-- != skip)
		*sptr = plen + 1;

	while(plen != 0)
		skip[(unsigned char)*ptrn++] = plen--;

	return skip;
}



/****************************************************************
 *
 *  Function: make_shift(char *, int)
 *
 *  Purpose: Create a Boyer-Moore shift table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the shift table
 *
 ****************************************************************/
int *make_shift(char *ptrn, int plen)
{
	int *shift = (int *)malloc(plen * sizeof(int));
	int *sptr = shift + plen - 1;
	char *pptr = ptrn + plen - 1;
	char c;

	if(shift == NULL)
	{
		return NULL;
	}

	c = ptrn[plen - 1];

	*sptr = 1;

	while(sptr-- != shift)
	{
		char *p1 = ptrn + plen - 2, *p2, *p3;

		do
		{
			while(p1 >= ptrn && *p1-- != c) ;

			p2 = ptrn + plen - 2;
			p3 = p1;

			while(p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr) ;
		}
		while(p3 >= ptrn && p2 >= pptr);

		*sptr = shift + plen - sptr + p2 - p3;

		pptr--;
	}

	return shift;
}



/****************************************************************
 *
 *  Function: search_substring(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int search_substring(char *buf, int blen, char *ptrn, int plen, int *skip, int *shift)
{
	int b_idx = plen;

	if(plen == 0)
		return 1;

	while(b_idx <= blen)
	{
		int p_idx = plen, skip_stride, shift_stride;

		while(buf[--b_idx] == ptrn[--p_idx])
		{
			if(b_idx < 0)
				return 0;

			if(p_idx == 0)
			{
				return 1;
			}
		}

		skip_stride = skip[(unsigned char)buf[b_idx]];
		shift_stride = shift[p_idx];

		b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
	}

	return 0;
}
