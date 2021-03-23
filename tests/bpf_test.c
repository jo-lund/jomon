#include <check.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include "../bpf/bpf.h"
#include "../bpf/parse.h"
#include "../bpf/pcap_parser.h"
#include "../mempool.h"
#include "../misc.h"

#define PATH "tests/bpf/"

START_TEST(filter_test)
{
    struct bpf_prog bpf1, bpf2;
    char buf[1024];
    FILE *fp;
    DIR *dfd;
    struct dirent *dp;
    int i = 1;

    if ((dfd = opendir(PATH)) == NULL)
        ck_abort_msg("opendir error");
    while ((dp = readdir(dfd)) != NULL) {
        char file[MAXPATH] = PATH;
        char *p = buf;

        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;
        strncat(file, dp->d_name, MAXPATH);
        if (!bpf_parse_init(file))
            ck_abort_msg("bpf_parse_init error");
        bpf1 = bpf_parse();
        if ((fp = fopen(file, "r")) == NULL)
            ck_abort_msg("fopen error");
        fgets(buf, 1024, fp);
        while (*p != '\0') {
            if (*p != ';')
                break;
            p++;
        }
        bpf2 = pcap_compile(p);
        ck_assert(bpf1.size == bpf2.size);
        ck_assert_msg(memcmp(bpf1.bytecode, bpf2.bytecode, bpf1.size * sizeof(struct bpf_insn)) == 0,
                      "Error: Filter %d: %s", i++, p);
        free(bpf1.bytecode);
        free(bpf2.bytecode);
        fclose(fp);
        break;
    }
    closedir(dfd);
    bpf_parse_free();
}
END_TEST

Suite *bpf_suite(void)
{
    Suite *s;
    TCase *tc_core;

    mempool_init();
    s = suite_create("bpf");
    tc_core = tcase_create("Core");
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, filter_test);
    tcase_set_timeout(tc_core, 60);
    mempool_free();
    return s;
}
