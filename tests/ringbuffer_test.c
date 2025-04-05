#include <check.h>
#include <time.h>
#include "ringbuffer.h"
#include "util.h"

#include <stdio.h>

START_TEST(ringbuffer_test_create)
{
    static const int nelems = 16;
    ringbuffer_t *data = ringbuffer_init(nelems);

    ck_assert(data);
    ck_assert_msg(ringbuffer_empty(data), "Ringbuffer should be empty");
    ck_assert_msg(ringbuffer_size(data) == 0, "Ringbuffer should contain 0 elements");
    ck_assert_msg(ringbuffer_capacity(data) == nelems - 1, "Ringbuffer's capacity should be %d but is %d",
                  nelems - 1, ringbuffer_capacity(data));
    ringbuffer_free(data);
}
END_TEST

START_TEST(ringbuffer_test_insert)
{
    static const int nelems = 8;
    ringbuffer_t *data = ringbuffer_init(8);

    for (int i = 0; i < nelems - 1; i++) {
        ringbuffer_push(data, INT_TO_PTR(i));
        ck_assert_msg(ringbuffer_capacity(data) == nelems - 1 - (i + 1),
                      "[%d]: Ringbuffer's capacity should be %d but is %d",
                      i, nelems - 1 - (i + 1), ringbuffer_capacity(data));
        ck_assert_msg(ringbuffer_size(data) == i + 1,
                      "[%d]: Ringbuffer's size should be %d but is %d",
                      i, i + 1, ringbuffer_size(data));
    }
    ck_assert_msg(ringbuffer_empty(data) == false, "Ringbuffer should not be empty");
    ck_assert_msg(ringbuffer_size(data) == nelems - 1, "Ringbuffer should contain %d elements but has %d",
                  nelems, ringbuffer_size(data));
    ck_assert_msg(ringbuffer_capacity(data) == 0, "Ringbuffer's capacity should be 0 but is %d",
                  ringbuffer_capacity(data));
    ringbuffer_free(data);
}
END_TEST

#define SIZE 4096
#define NREMOVE 500

START_TEST(ringbuffer_test_remove_and_traverse)
{
    ringbuffer_t *data = ringbuffer_init(SIZE);

    for (unsigned int i = 1; i < SIZE; i++) {
        ringbuffer_push(data, UINT_TO_PTR(i));
    }
    ck_assert_msg(ringbuffer_size(data) == SIZE - 1, "ringbuffer_size(data) == %d, but should be %d",
                  ringbuffer_size(data), SIZE - 1);
    ck_assert_msg(PTR_TO_UINT(ringbuffer_first(data)) == 1, "ringbuffer_first(data) == %lu, but should be 1",
                  PTR_TO_UINT(ringbuffer_first(data)));
    for (unsigned int i = 2; i < SIZE; i++) {
        ck_assert_msg(PTR_TO_UINT(ringbuffer_next(data)) == i, "ringbuffer_next(data) == %lu, but should be %u",
                      PTR_TO_UINT(ringbuffer_next(data)), i);
    }

    for (unsigned int i = 0; i < NREMOVE; i++) {
        ringbuffer_pop(data);
    }
    ck_assert_msg(ringbuffer_size(data) == SIZE - 1 - NREMOVE,
                  "Ringbuffer should contain %d elements, but has %d",
                  SIZE - 1 - NREMOVE, ringbuffer_size(data));
    ck_assert_msg(PTR_TO_UINT(ringbuffer_first(data)) == NREMOVE + 1,
                  "ringbuffer_first(data) == %lu, but should be %d",
                  PTR_TO_UINT(ringbuffer_first(data)), NREMOVE + 1);
    for (unsigned int i = NREMOVE + 2; i < SIZE; i++) {
        ck_assert_msg(PTR_TO_UINT(ringbuffer_next(data)) == i, "ringbuffer_next(data) == %lu, but should be %u",
                      PTR_TO_UINT(ringbuffer_next(data)), i);
    }

    /* insert removed elements */
    for (unsigned int i = 0; i < NREMOVE; i++) {
        ringbuffer_push(data, UINT_TO_PTR(SIZE - i - 1));
    }
    ck_assert_msg(ringbuffer_size(data) == SIZE - 1, "ringbuffer_size(data) == %d, but should be %d",
                  ringbuffer_size(data), SIZE - 1);
    ringbuffer_free(data);
}
END_TEST

Suite *ringbuffer_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ringbuffer");
    tc_core = tcase_create("Core");
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, ringbuffer_test_create);
    tcase_add_test(tc_core, ringbuffer_test_insert);
    tcase_add_test(tc_core, ringbuffer_test_remove_and_traverse);
    tcase_set_timeout(tc_core, 60);
    return s;
}
