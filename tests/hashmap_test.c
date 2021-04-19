#include <check.h>
#include <time.h>
#include "../util.h"
#include "../hashmap.h"
#include "../hashmap.c"
#include "../hash.h"

START_TEST(hashmap_test_create)
{
    hashmap_t *map = hashmap_init(10, NULL, NULL);

    ck_assert(map);
    ck_assert_msg(hashmap_size(map) == 0, "Hash table should be empty");
    hashmap_free(map);
}
END_TEST

START_TEST(hashmap_test_insert)
{
    char syms[] = { 'a', 'b', 'c', 'd' };
    hashmap_t *map = hashmap_init(20, NULL, NULL);

    for (unsigned int i = 0; i < sizeof(syms)/sizeof(char); i++)
        hashmap_insert(map, &syms[i], NULL);
    for (unsigned int i = 0; i < sizeof(syms)/sizeof(char); i++)
        ck_assert(syms[i] == * (char *) hashmap_get_key(map, &syms[i]));
    ck_assert_msg(hashmap_size(map) == 4, "Hash table should contain 4 elements");
    hashmap_clear(map);
    ck_assert_msg(hashmap_size(map) == 0, "Hash table should be empty");
    hashmap_free(map);
}
END_TEST

START_TEST(hashmap_test_insert_same)
{
    hashmap_t *map = hashmap_init(20, hashfnv_uint32, compare_uint);

    for (unsigned int i = 0; i < 20; i++) {
        hashmap_insert(map, UINT_TO_PTR(i), UINT_TO_PTR(i + 1));
        ck_assert(PTR_TO_UINT(hashmap_get_key(map, UINT_TO_PTR(i))) == i);
        ck_assert(PTR_TO_UINT(hashmap_get(map, UINT_TO_PTR(i))) == i + 1);
    }
    hashmap_insert(map, UINT_TO_PTR(5), UINT_TO_PTR(42));
    ck_assert(PTR_TO_UINT(hashmap_contains(map, UINT_TO_PTR(5))));
    ck_assert(PTR_TO_UINT(hashmap_get(map, UINT_TO_PTR(5))) == 42);
    hashmap_free(map);
}
END_TEST


#define SIZE 10000
#define REMOVE_MIN 1000
#define REMOVE_MAX 8000

START_TEST(hashmap_test_remove)
{
    hashmap_t *map = hashmap_init(1024, hashfnv_uint32, compare_uint);

    for (unsigned int i = 0; i < SIZE; i++) {
        hashmap_insert(map, UINT_TO_PTR(i), UINT_TO_PTR(i));
        ck_assert(PTR_TO_UINT(hashmap_get_key(map, UINT_TO_PTR(i))) == i);
        ck_assert(PTR_TO_UINT(hashmap_get(map, UINT_TO_PTR(i))) == i);
    }
    ck_assert_msg(hashmap_size(map) == SIZE, "Hash table should contain %d elements", SIZE);
    for (unsigned int i = REMOVE_MIN; i < REMOVE_MAX; i++) {
        hashmap_remove(map, UINT_TO_PTR(i));
        ck_assert(hashmap_get_key(map, UINT_TO_PTR(i)) == NULL);
    }
    ck_assert_msg(hashmap_size(map) == SIZE - (REMOVE_MAX - REMOVE_MIN),
                  "Hash table should contain %d elements", SIZE - (REMOVE_MAX - REMOVE_MIN));
    for (unsigned int i = 1; i < REMOVE_MIN; i++)
        ck_assert(PTR_TO_UINT(hashmap_get_key(map, UINT_TO_PTR(i))) == i);
    for (unsigned int i = REMOVE_MAX; i < SIZE; i++)
        ck_assert(PTR_TO_UINT(hashmap_get_key(map, UINT_TO_PTR(i))) == i);

    /* insert removed elements */
    for (unsigned int i = REMOVE_MIN; i < REMOVE_MAX; i++) {
        hashmap_insert(map, UINT_TO_PTR(i), UINT_TO_PTR(i + 1));
        ck_assert(PTR_TO_UINT(hashmap_get_key(map, UINT_TO_PTR(i))) == i);
        ck_assert(PTR_TO_UINT(hashmap_get(map, UINT_TO_PTR(i))) == i + 1);
    }
    ck_assert_msg(hashmap_size(map) == SIZE, "Hash table should contain %d elements", SIZE);
    hashmap_free(map);
}
END_TEST

START_TEST(hashmap_test_iterate)
{
    hashmap_t *map = hashmap_init(1024, hashfnv_uint32, compare_uint);
    const hashmap_iterator *it;
    const hashmap_iterator *prev;
    int c = 0;

    for (uint32_t i = 0; i < 500; i++) {
        hashmap_insert(map, UINT_TO_PTR(i), UINT_TO_PTR(i + 1));
        ck_assert(hashmap_contains(map, UINT_TO_PTR(i)));
    }
    HASHMAP_FOREACH(map, it) {
        ck_assert(PTR_TO_UINT(it->key) + 1 == PTR_TO_UINT(it->data));
        prev = it;
        c++;
    }
    ck_assert_msg(c == 500, "HASHMAP_FOREACH failed to traverse all elements: size = %d, count = %d",
                  hashmap_size(map), c);

    c = 0;
    while (prev) {
        ck_assert(PTR_TO_UINT(prev->key) + 1 == PTR_TO_UINT(prev->data));
        prev = hashmap_prev(map, prev);
        c++;
    }
    ck_assert_msg(c == 500, "hashmap_prev failed to traverse all elements: size = %d, count = %d",
                  hashmap_size(map), c);
    hashmap_free(map);
}
END_TEST

uint32_t hash_id(const void *key)
{
    return PTR_TO_UINT(key);
}

START_TEST(hashmap_test_id)
{
    hashmap_t *map = hashmap_init(16, hash_id, compare_uint);

    hashmap_insert(map, UINT_TO_PTR(0), UINT_TO_PTR(0));
    hashmap_insert(map, UINT_TO_PTR(~0), UINT_TO_PTR(~0));
    ck_assert(PTR_TO_UINT(hashmap_get(map, UINT_TO_PTR(0))) == 0);
    ck_assert(PTR_TO_UINT(hashmap_get(map, UINT_TO_PTR(~0))) == (uintptr_t) ~0);

    hashmap_insert(map, UINT_TO_PTR(2), UINT_TO_PTR(2));
    hashmap_insert(map, UINT_TO_PTR(18), UINT_TO_PTR(18));
    ck_assert(PTR_TO_UINT(hashmap_get(map, UINT_TO_PTR(2))) == 2);
    ck_assert(PTR_TO_UINT(hashmap_get(map, UINT_TO_PTR(18))) == 18);
    hashmap_remove(map, UINT_TO_PTR(2));
    ck_assert(hashmap_contains(map, UINT_TO_PTR(2)) == false);
    ck_assert(PTR_TO_UINT(hashmap_get(map, UINT_TO_PTR(18))) == 18);
    hashmap_free(map);
}
END_TEST

Suite *hashmap_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("hashmap");
    tc_core = tcase_create("Core");
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, hashmap_test_create);
    tcase_add_test(tc_core, hashmap_test_insert);
    tcase_add_test(tc_core, hashmap_test_insert_same);
    tcase_add_test(tc_core, hashmap_test_remove);
    tcase_add_test(tc_core, hashmap_test_iterate);
    tcase_add_test(tc_core, hashmap_test_id);
    tcase_set_timeout(tc_core, 60);
    return s;
}

int main()
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = hashmap_suite();
    sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return number_failed;
}
