#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int offset(int a, int b)
{
    if (a > b)
        return a - b;
    return b - a;
}

/* Borrowed from xpwn. */
void hexToInts(const char* hex, unsigned int** buffer, size_t* bytes)
{
    *bytes = strlen(hex) / 2;
    *buffer = (unsigned int*) malloc((*bytes) * sizeof(int));
    size_t i;
    for(i = 0; i < *bytes; i++)
    {
        sscanf(hex, "%2x", &((*buffer)[i]));
        hex += 2;
    }
}

#include <ctype.h>

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif

void hexdump(void *mem, unsigned int len)
{
    unsigned int i, j;

    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if(i % HEXDUMP_COLS == 0)
        {
            printf("0x%06x: ", i);
        }

        if((i+8) % 16 == 0)
        {
            printf("- ");
        }

        /* print hex data */
        if(i < len)
        {
            printf("%02x ", 0xFF & ((char*)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            printf("   ");
        }

        /* print ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if(j >= len) /* end of block, not really printing */
                {
                    putchar(' ');
                }
                else if(isprint(((char*)mem)[j])) /* printable char */
                {
                    putchar(0xFF & ((char*)mem)[j]);
                }
                else /* other char */
                {
                    putchar('.');
                }
            }
            putchar('\n');
        }
    }
}
