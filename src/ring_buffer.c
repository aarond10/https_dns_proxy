#include <stddef.h>
#include <stdio.h>   // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <stdlib.h>  // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <string.h>  // NOLINT(llvmlibc-restrict-system-libc-headers)

#include "ring_buffer.h"

struct ring_buffer
{
    char ** storage;
    uint32_t size;
    uint32_t next;  // next slot to use in storage
    uint8_t full;
} __attribute__((packed)) __attribute__((aligned(32)));

void ring_buffer_init(struct ring_buffer **rbp, uint32_t size)
{
    *rbp = NULL;
    if (size < 1) {
        return;
    }
    struct ring_buffer *rb = (struct ring_buffer *)calloc(1, sizeof(struct ring_buffer));
    if (!rb) {
        return;
    }
    rb->storage = (char**)calloc(size, sizeof(char*));
    if (!rb->storage) {
        free((void*) rb);
        return;
    }
    rb->size = size;
    *rbp = rb;
}

void ring_buffer_free(struct ring_buffer **rbp)
{
    struct ring_buffer *rb = *rbp;
    if (!rb->storage) {
        return;
    }
    for (uint32_t i = 0; i < rb->size; i++) {
        if (rb->storage[i]) {
            free(rb->storage[i]);
        }
    }
    free((void*) rb->storage);
    free((void*) rb);
    *rbp = NULL;
}

void ring_buffer_dump(struct ring_buffer *rb, FILE * file)
{
    if (!rb->storage) {
        return;
    }
    if (rb->next == 0 && !rb->full) {
        return; // empty
    }

    uint32_t current = rb->full ? rb->next : 0;
    do
    {
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        (void)fprintf(file, "%s\n", rb->storage[current]);

        if (++current == rb->size) {
            current = 0;
        }
    }
    while (current != rb->next);
    (void)fflush(file);
}

void ring_buffer_push_back(struct ring_buffer *rb, char* data, uint32_t size)
{
    if (!rb->storage) {
        return;
    }

    if (rb->storage[rb->next]) {
        free(rb->storage[rb->next]);
    }
    rb->storage[rb->next] = (char*)malloc(size + 1);
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memcpy(rb->storage[rb->next], data, size);
    rb->storage[rb->next][size] = '\0';

    if (++rb->next == rb->size) {
        rb->next = 0;
        rb->full = 1;
    }
}
