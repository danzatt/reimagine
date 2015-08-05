#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <openssl/aes.h>

#include "opensn0w-X/include/image3.h"
#include "opensn0w-X/include/util.h"
#include "opensn0w-X/include/structs.h"
#include "opensn0w-X/include/ibootsup.h"

#include "helper.h"

#define foreach_chunk(a) for (struct chunk *a = first_chunk; a != NULL; a = a->next)

#define ARM_BRANCH_OPCODE		"\x0e\x00\x00\xea"
#define OPCODE_LENGTH			4

unsigned int* key = NULL;
unsigned int* iv = NULL;

int hasKey = 0;
int hasIV = 0;
int shouldDump = 0;
int shouldList = 0;
int shouldPatch = 0;
const char *outfile = NULL;

size_t keysize;

struct chunk;

typedef struct chunk {
    struct chunk* next;
    void *data;
    size_t size;
} chunk;

struct chunk *first_chunk = NULL;
struct chunk *last_chunk = NULL;

void add_chunk(void* data, size_t size){
    struct chunk *my_chunk = _xmalloc(sizeof(chunk));

    if(first_chunk == NULL){
        first_chunk = my_chunk;
        last_chunk = my_chunk;
    };

    my_chunk->next = NULL;
    my_chunk->data = data;
    my_chunk->size = size;

    last_chunk->next = my_chunk;
    last_chunk = my_chunk;
}

void my_callback(Image3Header* tag)
{
    if(tag->magic == kImage3TagKeyBag)
        return;

    /*decrypt the image*/
    if(tag->magic == kImage3TagData && hasIV && hasKey)
    {
        /* Ported from xpwn. */
        uint8_t my_iv[16];
        int i;
        uint8_t bKey[32];

        int keyBits = keysize * 8;

        for(i = 0; i < 16; i++) {
            my_iv[i] = iv[i] & 0xff;
        }

        for(i = 0; i < (keyBits / 8); i++) {
            bKey[i] = key[i] & 0xff;
        }

        AES_KEY dec_key;
        AES_set_decrypt_key(bKey, keyBits, &dec_key);

        uint8_t ivec[16];
        memcpy(ivec, my_iv, 16);

        /* Decrypt date after the tag structure till dataSize aligned to the multiple of 16 (due to AES) */
        AES_cbc_encrypt((unsigned char *) (tag + 1), (unsigned char *) (tag + 1), (tag->dataSize / 16) * 16, &dec_key, ivec, AES_DECRYPT);
        /*AES_cbc_encrypt((char *) tag + sizeof(Image3Header), (char *) tag + sizeof(Image3Header), (tag->dataSize / 16) * 16, &dec_key, ivec, AES_DECRYPT);*/

        if (memcmp (tag + 1, ARM_BRANCH_OPCODE, OPCODE_LENGTH)) {
            printf("[W] This doesn't look like ARM image. You might have supplied wrong key/IV.\n");
        }

        if (shouldPatch)
        {
            struct mapped_image img;
            img.image = tag + 1;
            img.size = (tag->dataSize / 16) * 16;

            if (ibootsup_set_image(img) != 0)
                printf("[-] Couldn't set image for patching. Is this correct file ?\n");
            if (ibootsup_dynapatch () != 0)
                printf("[-] Couldn't patch file.\n");

        }

        /*dump only decrypted data*/
        if (outfile != NULL)
        {
            FILE* fd;
            fd = fopen(outfile, "wb");

            if (!fd){
                printf("[-] Can't open file for writing.\n");
            };

            fwrite(tag + 1, tag->size - sizeof(Image3Header), 1, fd);

            fclose(fd);
            exit(0);
        }
    }

    if (shouldList)
    {
        printf("Tag '%c%c%c%c' with data of size %u.\n",
               (char)(tag->magic >> 24),
               (char)(tag->magic >> 16),
               (char)(tag->magic >> 8),
               (char)(tag->magic),
               tag->dataSize);
    }

    if (shouldDump)
    {
        printf("Tag '%c%c%c%c' contains:\n",
               (char)(tag->magic >> 24),
               (char)(tag->magic >> 16),
               (char)(tag->magic >> 8),
               (char)(tag->magic));
        hexdump(tag + 1, tag->dataSize);
    }

    add_chunk(tag, tag->size);
};


int main(int argc, char* argv[])
{

    if(argc < 3) {
        printf("Usage: %s <infile> <outfile> -iv <IV> -k <key>\n", argv[0]);
        printf("\nOther options are:\n");
        printf("\t-d, --dump\tprint tag names and hexdump their content\n");
        printf("\t\t\t(Note: this option works on the final decrypted/patched file)\n");
        printf("\t-l, --list\tlist tag present in file\n");
        printf("\t-r, --raw\tdump the DATA tag to <outfile>\n");
        printf("\t-p, --patch\tpatch the file using ibootsup\n");
        return -1;
    }

    int argNo = 3;
    while(argNo < argc) {

        /*if(strcmp(argv[argNo], "-decrypt") == 0) {
            doDecrypt = 1;
            template = createAbstractFileFromFile(fopen(argv[1], "rb"));
            if(!template) {
                fprintf(stderr, "error: cannot open template\n");
                return 1;
            }
        }*/

        if(strcmp(argv[argNo], "-l") == 0 || strcmp(argv[argNo], "--list") == 0) {
            shouldList = 1;
        }

        if(strcmp(argv[argNo], "-d") == 0 || strcmp(argv[argNo], "--dump") == 0) {
            shouldDump = 1;
        }

        if(strcmp(argv[argNo], "-r") == 0 || strcmp(argv[argNo], "--raw") == 0) {
            outfile = argv[2];
        }

        if(strcmp(argv[argNo], "-p") == 0 || strcmp(argv[argNo], "--patch") == 0) {
            shouldPatch = 1;
        }

        if(strcmp(argv[argNo], "-k") == 0 && (argNo + 1) < argc) {
            hexToInts(argv[argNo + 1], &key, &keysize);
            printf("keysize is %zu\n", keysize);

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

    void *image_buffer = NULL;

    assert(!image3_map_file(argv[1], &image_buffer));

    Image3RootHeader *orig = image_buffer;
/*
    printf("orig offset is %u\n", orig->shshExtension.shshOffset);
    printf("orig size is %u\n", orig->header.dataSize);
*/

    image3_iterate_tags(image_buffer, &my_callback);

    int shsh;
    int data;

    size_t total_size = 0;

    foreach_chunk(i)
        total_size += i->size;

    /*printf("total_size %zu\n", total_size);*/

    uint8_t *out_buffer = _xmalloc(total_size + sizeof(Image3RootHeader));

    /* skip the root header, we'll get back to it later */
    size_t next_free = sizeof(Image3RootHeader);

    int chunks = 0;
    foreach_chunk(i)
    {
        uint32_t *magic = i->data;

        /*printf("Parsing chunk '%c%c%c%c'\n",
               (char)(*magic >> 24),
               (char)(*magic >> 16),
               (char)(*magic >> 8),
               (char)(*magic));*/

        if(*magic == kImage3TagData)
            shsh = (uint32_t) next_free;
        if(*magic == kImage3TagSignature)
            data = (uint32_t) next_free;

        memcpy(out_buffer + next_free, i->data, i->size);
        next_free += i->size;
        chunks++;
    }

/*
    printf("%u chunks\n", chunks);
    printf("shsh %u data %u offset %u\n", shsh, data, offset(data, shsh) + 32);
*/

    Image3RootHeader *out_header = (Image3RootHeader *) out_buffer;
    out_header->header.magic = kImage3Magic;
    out_header->header.size = total_size + sizeof(Image3RootHeader);
    out_header->header.dataSize = total_size;

    out_header->shshExtension.shshOffset = offset(data, shsh) + 32;
    out_header->shshExtension.imageType = orig->shshExtension.imageType;

    FILE* fd;
    fd = fopen(argv[2],"wb");

    if (!fd){
        printf("[-] Can't open file for writing.\n");
        return -1;
    };

    fwrite(out_buffer, total_size + sizeof(Image3RootHeader), 1, fd);

    fclose(fd);

    return 0;
}
