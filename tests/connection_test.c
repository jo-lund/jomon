#include <check.h>
#include <stdio.h>
#include "mempool.h"
#include "jomon.h"
#include "file.h"
#include "decoder/packet.h"
#include "decoder/decoder.h"
#include "decoder/tcp_analyzer.h"

#define PATH "tests/decoder/"

static iface_handle_t *handle;
static unsigned char buf[SNAPLEN];
static struct packet *p;

static bool handle_packet(iface_handle_t *handle, unsigned char *buf, uint32_t n,
                          struct timeval *t)
{
    if (!decode_packet(handle, buf, n, &p))
        return false;
    p->time.tv_sec = t->tv_sec;
    p->time.tv_usec = t->tv_usec;
    tcp_analyzer_check_stream(p);
    return true;
}

static void setup(void)
{
    mempool_init();
    decoder_init();
    tcp_analyzer_init();
    handle = iface_handle_create(buf, SNAPLEN, handle_packet);
}

static void teardown(void)
{
    decoder_exit();
    tcp_analyzer_free();
    mempool_destruct();
    free(handle);
}

static void read_file(const char *path)
{
    enum file_error err;
    FILE *fp;

    if ((fp = file_open(path, "r", &err)) == NULL)
        ck_abort_msg("file_open error");
    if ((err = file_read(handle, fp, handle_packet)) != NO_ERROR) {
        fclose(fp);
        ck_abort_msg("Error in %s: %s", path, file_error(err));
    }
    fclose(fp);
}

START_TEST(connection_test)
{
    hashmap_t *conn;

    read_file(PATH "conn.pcap");
    conn = tcp_analyzer_get_sessions();
    ck_assert_msg(hashmap_size(conn) == 1, "Wrong number of connections: %d != 1",
                  hashmap_size(conn));
}
END_TEST

Suite *connection_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("connection");
    tc_core = tcase_create("Core");
    suite_add_tcase(s, tc_core);
    tcase_add_unchecked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, connection_test);
    tcase_set_timeout(tc_core, 60);
    return s;
}
