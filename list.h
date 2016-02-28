typedef struct node node_t;

/* insert element at the front */
void push_front(void *data);

/* insert element at the end */
void push_back(void *data);

/* remove element from the front */
void pop_front();

/* remove element from the end */
void pop_back();

/* clear the list */
void clear_list();

const void *front();

const void *back();

const node_t *begin();

const node_t *end();

const node_t *get_prev(const node_t *n);

const node_t *get_next(const node_t *n);

const void *get_data(const node_t *n);

