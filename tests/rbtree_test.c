#include <check.h>
#include <time.h>
#include "util.h"
#include "rbtree.h"
#include "hash.h"

#include <stdio.h>

START_TEST(rbtree_test_create)
{
    rbtree_t *tree = rbtree_init(compare_uint, NULL);

    ck_assert(tree);
    ck_assert_msg(rbtree_size(tree) == 0, "Red Black tree should be empty");
    rbtree_free(tree);
}
END_TEST

START_TEST(rbtree_test_insert)
{
    char syms[] = { 'a', 'b', 'c', 'd' };
    rbtree_t *tree = rbtree_init(compare_uint, NULL);

    for (unsigned int i = 0; i < ARRAY_SIZE(syms); i++)
        rbtree_insert(tree, &syms[i], &syms[i]);
    for (unsigned int i = 0; i < ARRAY_SIZE(syms); i++)
        ck_assert(syms[i] == * (char *) rbtree_data(tree, &syms[i]));
    ck_assert_msg(rbtree_size(tree) == 4, "Red Black tree should contain 4 elements");
    rbtree_clear(tree);
    ck_assert_msg(rbtree_size(tree) == 0, "Red Black tree should be empty");
    rbtree_free(tree);
}
END_TEST

#define SIZE 1000
#define REMOVE_MIN 100
#define REMOVE_MAX 800

START_TEST(rbtree_test_remove)
{
    rbtree_t *tree = rbtree_init(compare_uint, NULL);

    for (unsigned int i = 0; i < SIZE; i++) {
        rbtree_insert(tree, UINT_TO_PTR(i), UINT_TO_PTR(i));
        ck_assert(PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(i))) == i);
    }
    ck_assert_msg(rbtree_size(tree) == SIZE, "Red Black tree should contain %d elements", SIZE);

    for (unsigned int i = REMOVE_MIN; i < REMOVE_MAX; i++) {
        rbtree_remove(tree, UINT_TO_PTR(i));
        ck_assert(rbtree_contains(tree, UINT_TO_PTR(i)) == false);
    }
    ck_assert_msg(rbtree_size(tree) == SIZE - (REMOVE_MAX - REMOVE_MIN),
                  "Red Black tree should contain %d elements", SIZE - (REMOVE_MAX - REMOVE_MIN));
    for (unsigned int i = 1; i < REMOVE_MIN; i++)
        ck_assert_msg(PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(i))) == i,
                      "Red Black tree should contain element key:%d == data:%lu", i,
                      PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(i))));
    for (unsigned int i = REMOVE_MAX; i < SIZE; i++)
        ck_assert_msg(PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(i))) == i,
                      "Red Black tree should contain element key:%d == data:%lu", i,
                      PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(i))));

    /* insert removed keys with new data */
    for (unsigned int i = REMOVE_MIN; i < REMOVE_MAX; i++) {
        rbtree_insert(tree, UINT_TO_PTR(i), UINT_TO_PTR(i + 1));
        ck_assert(PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(i))) == i + 1);
    }
    ck_assert_msg(rbtree_size(tree) == SIZE, "Red Black tree should contain %d elements", SIZE);
    rbtree_free(tree);
}
END_TEST

START_TEST(rbtree_test_iterate)
{
    rbtree_t *tree = rbtree_init(compare_uint, NULL);
    const rbtree_node_t *n;
    int c = 0;

    for (uint32_t i = 0; i < 500; i++) {
        rbtree_insert(tree, UINT_TO_PTR(i), UINT_TO_PTR(i + 1));
        ck_assert(rbtree_contains(tree, UINT_TO_PTR(i)));
    }
    RBTREE_FOREACH(tree, n) {
        ck_assert(PTR_TO_UINT(rbtree_get_key(n)) + 1 == PTR_TO_UINT(rbtree_get_data(n)));
        c++;
    }
    ck_assert_msg(c == 500, "RBTREE_FOREACH failed to traverse all elements: size = %d, count = %d",
                  rbtree_size(tree), c);
    rbtree_free(tree);
}
END_TEST

START_TEST(rbtree_test_data)
{
    rbtree_t *tree = rbtree_init(compare_uint, NULL);

    rbtree_insert(tree, UINT_TO_PTR(0), UINT_TO_PTR(0));
    rbtree_insert(tree, UINT_TO_PTR(~0), UINT_TO_PTR(~0));
    ck_assert(PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(0))) == 0);
    ck_assert(PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(~0))) == (uintptr_t) ~0);
    rbtree_insert(tree, UINT_TO_PTR(2), UINT_TO_PTR(2));
    rbtree_insert(tree, UINT_TO_PTR(18), UINT_TO_PTR(18));
    ck_assert(PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(2))) == 2);
    ck_assert(PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(18))) == 18);
    rbtree_remove(tree, UINT_TO_PTR(2));
    ck_assert(rbtree_contains(tree, UINT_TO_PTR(2)) == false);
    ck_assert(PTR_TO_UINT(rbtree_data(tree, UINT_TO_PTR(18))) == 18);
    rbtree_free(tree);
}
END_TEST

Suite *rbtree_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("rbtree");
    tc_core = tcase_create("Core");
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, rbtree_test_create);
    tcase_add_test(tc_core, rbtree_test_insert);
    tcase_add_test(tc_core, rbtree_test_remove);
    tcase_add_test(tc_core, rbtree_test_iterate);
    tcase_add_test(tc_core, rbtree_test_data);
    tcase_set_timeout(tc_core, 60);
    return s;
}
