#include <check.h>
#include "test.h"

int main()
{
    int number_failed;
    SRunner *sr;

    sr = srunner_create(hashmap_suite());
    srunner_add_suite(sr, bpf_suite());
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return number_failed;
}
