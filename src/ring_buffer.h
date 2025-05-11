#ifndef _RING_BUFFER_H_
#define _RING_BUFFER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct ring_buffer;

void ring_buffer_init(struct ring_buffer **rbp, uint32_t size);
void ring_buffer_free(struct ring_buffer **rbp);
void ring_buffer_dump(struct ring_buffer *rb, FILE * file);
void ring_buffer_push_back(struct ring_buffer *rb, char* data, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // RING_BUFFER_H_
