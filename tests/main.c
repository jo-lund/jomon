#include <check.h>
#include <stdlib.h>
#include "test.h"

void monitor_exit(int status)
{
    exit(status);
}

int main()
{
    int number_failed;
    SRunner *sr;

    sr = srunner_create(hashmap_suite());
    srunner_add_suite(sr, bpf_suite());
    srunner_add_suite(sr, rbtree_suite());
    srunner_add_suite(sr, decoder_suite());
    srunner_add_suite(sr, vector_suite());
    srunner_run(sr, "bpf", "Core", CK_NORMAL);
    srunner_run(sr, "hashmap", "Core", CK_NORMAL);
    srunner_run(sr, "rbtree", "Core", CK_NORMAL);
    srunner_run(sr, "decoder", "Core", CK_NORMAL);
    srunner_run(sr, "vector", "Core", CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return number_failed;
}
