#ifndef __MSTRING_H__
#define __MSTRING_H__

int contains_substring(char *, int, char *, int);
int search_substring(char *, int, char *, int, int *, int *);
int *make_skip(char *, int);
int *make_shift(char *, int);

#endif							 /* __MSTRING_H__ */
