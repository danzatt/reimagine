#ifndef __HELPER_H
#define __HELPER_H

int offset(int a, int b);
void hexToInts(const char* hex, unsigned int** buffer, size_t* bytes);
void hexdump(void *mem, unsigned int len);

#endif
