/*
 *  Copyright 2015, danzatt <twitter.com/danzatt>
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>

#include "opensn0w-X/include/image3.h"
#include "opensn0w-X/include/util.h"
#include "opensn0w-X/include/structs.h"
#include "opensn0w-X/include/ibootsup.h"
#include "opensn0w-X/include/kcache.h"

#define __target_arm__
#include "opensn0w-X/include/macho.h"
#undef __target_arm__

#include "helper.h"

#define foreach_chunk(a) for (struct chunk *a = first_chunk; a != NULL; a = a->next)

#define ARM_BRANCH_OPCODE		"\x0e\x00\x00\xea"
#define OPCODE_LENGTH			4

#define PRINT_MAGIC(a)                  \
            printf("'%c%c%c%c'",        \
                    (char)(a >> 24),    \
                    (char)(a >> 16),    \
                    (char)(a >> 8),     \
                    (char)(a))          \


//#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( 0 )
#else
#define DEBUG_PRINT(...) do{ } while ( 0 )
#endif

char *outfile = NULL;

unsigned int* key = NULL;
unsigned int* iv = NULL;

int hasKey = 0;
int hasIV = 0;
int shouldDump = 0;
int shouldList = 0;
int shouldPatch = 0;
int dumpData = 0;
int shouldDecompress = 0;

size_t keysize;

struct chunk;

typedef struct chunk {
    struct chunk* next;
    void *data;
    size_t size;
} chunk;

struct chunk *first_chunk = NULL;

void add_chunk(void *data, size_t size){
#ifdef DEBUG
    uint32_t *magic = data;
    printf("adding chunk ");
    PRINT_MAGIC(*magic);
    printf("\n");
#endif

    struct chunk *my_chunk = _xmalloc(sizeof(chunk));
    my_chunk->data = data;
    my_chunk->size = size;
    my_chunk->next = NULL;

    if (first_chunk == NULL)
    {
        first_chunk = my_chunk;
        return;
    }

    struct chunk *a = first_chunk;
    while (a->next != NULL)
        a = a->next;

    a->next = my_chunk;
}

int verify_data(const uint32_t magic, const void *buffer)
{

    switch (magic)
    {
        case kImage3TypeiBSS:
        case kImage3TypeiBEC:
        case kImage3TypeiBoot:
        case kImage3TypeiLLB:
        {
            if (memcmp(buffer, ARM_BRANCH_OPCODE, OPCODE_LENGTH))
            {
                printf("[W] This doesn't look like ARM image.\n");
                return 0;
            }
            else
            {
                printf("[i] This looks like ARM image.\n");
                return 1;
            }
        }

        case kImage3TypeKernel:
        {
            uint32_t *byte_ptr = (uint32_t *) buffer;
            DEBUG_PRINT("kernel magic 0x%x\n", kern_magic);

            switch (*byte_ptr)
            {
                case kMachCigam:
                {
                    printf("[i] This is endian swapped MachO file.\n");
                    return 1;
                }
                case kMachMagic:
                {
                    printf("[i] This is MachO file.\n");
                    return 1;
                }
                case __builtin_bswap32('comp'):
                {
                    if ( *(byte_ptr + 1) == __builtin_bswap32 ('lzss'))
                        printf("[i] This is lzss compressed kernel.\n");
                    else
                        printf("[i] This is compressed kernel.\n");
                    return 1;
                }
                default:
                {
                    printf("[W] This doesn't look like kernel.\n");
                    return 0;
                }
            }
        }

        case kImage3TypeDeviceTree:
        {
            /* borrowed from J (http://newosxbook.com/src.jl?tree=listings&file=6-bonus.c) */
            typedef struct OpaqueDTEntry {
                uint32_t            nProperties;    // Number of props[] elements (0 => end)
                uint32_t            nChildren;      // Number of children[] elements
            } DeviceTreeNode;

            DeviceTreeNode *dtn = (DeviceTreeNode *) buffer;
            if (dtn->nProperties > 20)
            {
                printf ("[W] Device tree has more than 20 properties.\n");
                return 0;
            }
            return 1;
        }

        default:
        {
            printf("[W] Don't support verifying ");
            PRINT_MAGIC(magic);
            printf(" files. You should check if the decryption went good manually.\n");
            return 1;
        }
    }
}

void my_callback(Image3Header *tag, Image3RootHeader *root)
{
    int chunk_added = 0;

    /* remove KBAG if we're decrypting */
    if(tag->magic == kImage3TagKeyBag && hasIV && hasKey)
        return;

    /* decrypt the image */
    if(tag->magic == kImage3TagData)
    {
        void *out_buff = (tag + 1);
        int out_size = tag->dataSize;

        if (hasIV && hasKey)
        {
            /* Ported from xpwntool & decodeimg3.pl */
            uint8_t my_iv[16];
            int i;
            uint8_t bKey[32];

            int keyBits = keysize * 8;

            for (i = 0; i < 16; i++)
            {
                my_iv[i] = iv[i] & 0xff;
            }

            for (i = 0; i < (keyBits / 8); i++)
            {
                bKey[i] = key[i] & 0xff;
            }

            AES_KEY dec_key;
            AES_set_decrypt_key(bKey, keyBits, &dec_key);

            uint8_t ivec[16];
            memcpy(ivec, my_iv, 16);

            int size = tag->dataSize + (16 - (tag->dataSize % 16));
            void *buf = _xmalloc(size);
            memcpy(buf, (tag + 1), size);

            AES_cbc_encrypt((unsigned char *) (buf),
                            (unsigned char *) (buf),
                            size,
                            &dec_key,
                            ivec,
                            AES_DECRYPT);

            if(!verify_data(root->shshExtension.imageType, buf))
                printf("[W] You might have supplied wrong key/IV.\n");

            out_buff = buf;
            out_size = size;

        }

        if (shouldPatch && (root->shshExtension.imageType == kImage3TypeiBoot ||
                            root->shshExtension.imageType == kImage3TypeiBEC ||
                            root->shshExtension.imageType == kImage3TypeiBSS ||
                            root->shshExtension.imageType == kImage3TypeiLLB))
        {
            struct mapped_image img;
            img.image = (uint8_t *) out_buff;
            img.size = out_size;

            if (ibootsup_set_image(img) != 0)
                printf("[-] Couldn't set image for patching. Is this correct file ?\n");
            if (ibootsup_dynapatch () != 0)
                printf("[-] Couldn't patch file.\n");

        }

        if (shouldDecompress && root->shshExtension.imageType == kImage3TypeKernel)
        {
            int decompressed_size = 0;
            void *decompressed;

            if (kcache_decompress_kernel (out_buff, NULL, &decompressed_size)) {
                printf("[-] Cannot decompress kernel.\n");
                goto cont;
            }

            printf ("[i] decompressed kernelcache size %d\n", decompressed_size);
            decompressed = _xmalloc (decompressed_size);
            if (kcache_decompress_kernel (out_buff, decompressed, &decompressed_size)) {
                free (decompressed);
                printf("[-] Cannot decompress kernel.\n");
                goto cont;
            }

            verify_data(root->shshExtension.imageType, decompressed);

            out_buff = decompressed;
            out_size = decompressed_size;
        }

        Image3Header *new_tag = _xmalloc(sizeof(Image3Header));

        new_tag->magic = tag->magic;
        new_tag->dataSize = out_size;
        new_tag->size = new_tag->dataSize + sizeof(Image3Header);

        if (!dumpData) /* omit the header if we're just dumping data */
                    add_chunk(new_tag, sizeof(Image3Header));

        add_chunk(out_buff, out_size);
        chunk_added = 1;
    }

    cont:

    if (shouldList && !shouldDump)
    {
        PRINT_MAGIC(tag->magic);
        printf(" (size: 0x%x\t dataSize: \t0x%x)\n", tag->size, tag->dataSize);
    }

    if (shouldDump)
    {
        PRINT_MAGIC(tag->magic);
        printf(" (size: 0x%x\t dataSize: \t0x%x):\n", tag->size, tag->dataSize);
        hexdump(tag + 1, tag->dataSize);
    }

    if (!chunk_added)
    {
        /* if dumpData is set we only want DATA tag */
        if (dumpData && tag->magic == kImage3TagData)
        {
            add_chunk((tag+1), tag->size - sizeof(Image3Header));
        }

        if (!dumpData)
        {
            add_chunk(tag, tag->size);
        }
    }
};


int main(int argc, char* argv[])
{

    if(argc < 3) {
        printf("Usage: %s <infile> [<outfile>] <options>\n", argv[0]);
        printf("\n<options> are:\n");
        printf("\t-iv <IV>\tset IV for decryption\n");
        printf("\t-k <key>\tset key for decryption\n");
        printf("\t-d, --dump\tprint tag names and hexdump their content\n");
        printf("\t\t\t(Note: this option works on the final decrypted/patched file)\n");
        printf("\t-l, --list\tlist tags present in file\n");
        printf("\t-r, --raw\tdump the DATA tag to <outfile>\n");
        printf("\t-p, --patch\tpatch the file using ibootsup\n");
        printf("\t-x, --decompress\tdecompress lzss compressed kernelcache\n");
        printf("\nCopyright 2015, danzatt <twitter.com/danzatt>\n");
        printf("You should have received a copy of the GNU General Public License and source code along with "
                       "this program. If you haven't, you should ask your source to provide one.\n");
        printf("\nThanks to winocm for opensn0w-X, guys behind xpwntool and decodeimg3.pl for decryption logic, J from "
                       "newosxbook.com for device tree headers.\n");
        return -1;
    }

    int argNo;

    if (argv[2][0] == '-')
        argNo = 2;
    else
    {
        argNo = 3;
        outfile = argv[2];
    }

    while(argNo < argc) {
        if(strcmp(argv[argNo], "-l") == 0 || strcmp(argv[argNo], "--list") == 0) {
            shouldList = 1;
        }

        if(strcmp(argv[argNo], "-d") == 0 || strcmp(argv[argNo], "--dump") == 0) {
            shouldDump = 1;
        }

        if(strcmp(argv[argNo], "-r") == 0 || strcmp(argv[argNo], "--raw") == 0) {
            dumpData = 1;
        }

        if(strcmp(argv[argNo], "-p") == 0 || strcmp(argv[argNo], "--patch") == 0) {
            shouldPatch = 1;
        }

        if(strcmp(argv[argNo], "-x") == 0 || strcmp(argv[argNo], "--decompress") == 0) {
            shouldDecompress = 1;
        }

        if(strcmp(argv[argNo], "-k") == 0 && (argNo + 1) < argc) {
            hexToInts(argv[argNo + 1], &key, &keysize);

            if(keysize % 8 != 0)
                printf("[-] Check your key, it has to be 16, 24 or 32 bytes.\n");
            else
                hasKey = 1;
        }

        if(strcmp(argv[argNo], "-iv") == 0 && (argNo + 1) < argc) {
            size_t bytes;
            hexToInts(argv[argNo + 1], &iv, &bytes);

            if(bytes != 16)
                printf("[-] Check your IV, it has to be 16 bytes.\n");
            else
                hasIV = 1;
        }

        argNo++;
    }

    if (outfile == NULL)
    {
        char *trailer = _xmalloc(21);

        if (hasKey && hasIV)
            strcat(trailer, ".dec");

        if (shouldPatch)
            strcat(trailer, ".pwn");

        if (dumpData)
            strcat(trailer, ".raw");

        if (shouldDecompress)
            strcat(trailer, ".macho");

        if (trailer[0] != '\0')
        {
            outfile = _xmalloc(strlen(argv[1]) + strlen(trailer) + 1);
            strcat(outfile, argv[1]);
            strcat(outfile, trailer);
        }

        free(trailer);
    }

    DEBUG_PRINT("outfile is %s\n", outfile);

    void *image_buffer = NULL;

    if (image3_map_file(argv[1], &image_buffer) != 0)
    {
        printf("[-] Can't open file.\n");
        return -1;
    }

    if (image_buffer == NULL)
    {
        printf("[-] error\n");
        return -1;
    }

    Image3RootHeader *orig = image_buffer;

    if (shouldDump || shouldList)
    {
        printf("Root magic: \t");
        PRINT_MAGIC(orig->header.magic);
        printf("\nRoot size: \t0x%x\n", orig->header.size);
        printf("Root data size: \t0x%x\n", orig->header.dataSize);

        printf("Root image type: \t");
        PRINT_MAGIC(orig->shshExtension.imageType);
        printf("\nRoot shsh offset: \t0x%x\n", orig->shshExtension.shshOffset);
    }

    image3_iterate_tags(image_buffer, &my_callback);

    size_t total_size = 0;
    foreach_chunk(i)
        total_size += i->size;

    DEBUG_PRINT("total_size %zu\n", total_size);

    /*......................................................... ˅ if we just want to dump DATA we don't add root header*/
    uint8_t *out_buffer = _xmalloc(total_size + (dumpData ? 0 : sizeof(Image3RootHeader)));

    if (!dumpData)
    {
        /* skip the root header, we'll get back to it later */
        size_t next_free = sizeof(Image3RootHeader);

        int shsh = 0;
        int data = 0;
        foreach_chunk(i)
        {
            uint32_t *magic = i->data;

#ifdef DEBUG
            printf("Parsing chunk ");
            PRINT_MAGIC(*magic);
            printf("\n");
#endif

            if (*magic == kImage3TagData)
                data = (uint32_t) next_free;
            if (*magic == kImage3TagSignature)
                shsh = (uint32_t) next_free;

            memcpy(out_buffer + next_free, i->data, i->size);
            next_free += i->size;
        }

        /* SHSH tag is not always present, if it isn't we use the end of file (next_free) in calculating offset */
        shsh = shsh ? shsh : next_free;

        DEBUG_PRINT("shsh %u data %u offset %u\n", shsh, data, offset(data, shsh) + 32);

        Image3RootHeader *out_header = (Image3RootHeader *) out_buffer;
        out_header->header.magic = kImage3Magic;
        out_header->header.size = total_size + sizeof(Image3RootHeader);
        out_header->header.dataSize = total_size;

        out_header->shshExtension.shshOffset = offset(data, shsh) + 32;
        out_header->shshExtension.imageType = orig->shshExtension.imageType;
    }
    else
    {
        size_t next_free = 0;
        foreach_chunk(i)
        {
#ifdef DEBUG
            uint32_t *magic = i->data;
            printf("Parsing chunk ");
            PRINT_MAGIC(*magic);
            printf("\n");
#endif
            memcpy(out_buffer + next_free, i->data, i->size);
            next_free += i->size;
        }
    }

    if (outfile != NULL)
    {
        FILE *fd;
        fd = fopen(outfile, "wb");

        if (!fd)
        {
            printf("[-] Can't open file for writing.\n");
            return -1;
        };

        fwrite(out_buffer, total_size + sizeof(Image3RootHeader), 1, fd);

        fclose(fd);
    }

    return 0;
}
