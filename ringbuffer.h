#include <stdbool.h>

typedef struct ringbuffer ringbuffer_t;

/* Initialize the buffer */
ringbuffer_t *ringbuffer_init(const int size);

/* Free all resources related to the buffer */
void ringbuffer_free(ringbuffer_t *rb);

/* Add an element to the buffer */
void ringbuffer_push(ringbuffer_t *rb, void *data);

/* Remove an element from the buffer */
void *ringbuffer_pop(ringbuffer_t *rb);

/* Return the occupancy of the buffer */
int ringbuffer_size(ringbuffer_t *rb);

/* Return the remaining capacity of the buffer */
int ringbuffer_capacity(ringbuffer_t *rb);

/* Is the buffer empty? */
bool ringbuffer_empty(ringbuffer_t *rb);

/* Return the first element in the buffer */
const void *ringbuffer_first(ringbuffer_t *rb);

/* Return the next element in buffer */
const void *ringbuffer_next(ringbuffer_t *rb);
