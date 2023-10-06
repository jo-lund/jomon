#include <check.h>
#include <time.h>
#include "vector.h"
#include "util.h"

START_TEST(vector_test_create)
{
    vector_t *data = vector_init(10);

    ck_assert(data);
    ck_assert_msg(vector_size(data) == 0, "Vector should be empty");
    vector_free(data, NULL);
}
END_TEST

START_TEST(vector_test_insert)
{
    static const int nelems = 10;
    vector_t *data = vector_init(10);

    for (int i = 0; i < nelems; i++)
        vector_push_back(data, INT_TO_PTR(i));
    for (int i = 0; i < nelems; i++)
        ck_assert(i == PTR_TO_INT(vector_get(data, i)));
    ck_assert_msg(vector_size(data) == nelems, "Vector should contain %d elements", nelems);
    vector_clear(data, NULL);
    ck_assert_msg(vector_size(data) == 0, "Vector should be empty");
    vector_free(data, NULL);
}
END_TEST

#define SIZE 10000
#define NREMOVE 500

START_TEST(vector_test_remove)
{
    vector_t *data = vector_init(1024);

    for (unsigned int i = 0; i < SIZE; i++) {
        vector_push_back(data, UINT_TO_PTR(i));
        ck_assert(PTR_TO_UINT(vector_get(data, i)) == i);
    }
    ck_assert_msg(vector_size(data) == SIZE, "Vector should contain %d elements", SIZE);
    for (unsigned int i = 0; i < NREMOVE; i++) {
        ck_assert(PTR_TO_UINT(vector_get(data, SIZE - i - 1)) == SIZE - i - 1);
        vector_pop_back(data, NULL);
        ck_assert(vector_get(data, SIZE - i - 1) == NULL);
    }
    ck_assert_msg(vector_size(data) == SIZE - NREMOVE,
                  "Vector should contain %d elements", SIZE - NREMOVE);

    /* insert removed elements */
    for (unsigned int i = 0; i < NREMOVE; i++) {
        vector_push_back(data, UINT_TO_PTR(SIZE - i - 1));
        ck_assert(PTR_TO_UINT(vector_back(data)) == SIZE - i - 1);
    }
    ck_assert_msg(vector_size(data) == SIZE, "Vector should contain %d elements", SIZE);
    vector_free(data, NULL);
}
END_TEST

START_TEST(vector_test_data)
{
    static const int size = 4096;
    vector_t *data = vector_init(size);
    int **array = NULL;

    for (int i = 0; i < size; i++)
        vector_push_back(data, INT_TO_PTR(i + 1));
    ck_assert_msg(vector_size(data) == size, "Vector should contain %d elements", size);
    for (int i = 0; i < size; i++)
        ck_assert(PTR_TO_INT(vector_get(data, i)) == i + 1);
    array = (int **) vector_data(data);
    ck_assert(array != NULL);
    for (int i = 0; i < size; i++) {
        ck_assert(PTR_TO_INT(array[i]) == i + 1);
        ck_assert(PTR_TO_INT(array[i]) == PTR_TO_INT(vector_get(data, i)));
    }
}
END_TEST

Suite *vector_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("vector");
    tc_core = tcase_create("Core");
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, vector_test_create);
    tcase_add_test(tc_core, vector_test_insert);
    tcase_add_test(tc_core, vector_test_remove);
    tcase_add_test(tc_core, vector_test_data);
    tcase_set_timeout(tc_core, 60);
    return s;
}
