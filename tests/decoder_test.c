#include <check.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include "mempool.h"
#include "misc.h"
#include "file.h"
#include "decoder/packet.h"
#include "decoder/decoder.h"
#include "ui/print_protocol.h"

#define PATH "tests/decoder/"

typedef struct vector vector_t;

main_context ctx;
vector_t *packets;
static iface_handle_t *handle;
static unsigned char buf[SNAPLEN];
static struct packet *p;

void stop_capture(void)
{
}

void start_capture(void)
{
}

struct packet_data *get_pdata(const struct packet *p, uint32_t id)
{
    struct packet_data *pdata = p->root;

    while (pdata) {
        if (get_protocol_key(pdata->id) == id)
            return pdata;
        pdata = pdata->next;
    }
    return NULL;
}

static bool handle_packet(iface_handle_t *handle, unsigned char *buf, uint32_t n,
                          struct timeval *t)
{
    if (!decode_packet(handle, buf, n, &p))
        return false;
    p->time.tv_sec = t->tv_sec;
    p->time.tv_usec = t->tv_usec;
    return true;
}

static void setup(void)
{
    mempool_init();
    decoder_init();
    handle = iface_handle_create(buf, SNAPLEN, handle_packet);
}

static void teardown(void)
{
    decoder_exit();
    mempool_destruct();
    free(handle);
}

START_TEST(snap_test)
{
    enum file_error err;
    FILE *fp;
    unsigned char oui[3] = { 0, 0x60, 0x1d };
    uint16_t pid = 1;
    struct packet_data *pdata;
    struct snap_info *snap;
    char log[MAXLINE];
    char out[MAXLINE];
    int n;

    if ((fp = file_open(PATH "snap.pcap", "r", &err)) == NULL)
        ck_abort_msg("file_open error");
    if ((err = file_read(handle, fp, handle_packet)) != NO_ERROR) {
        fclose(fp);
        ck_abort_msg("Error in %s: %s", "snap.pcap", file_error(err));
    }
    fclose(fp);
    pdata = get_pdata(p, ETH_802_SNAP);
    ck_assert_msg(pdata, "Not a SNAP packet");
    snap = pdata->data;
    ck_assert(snap);
    ck_assert_msg(memcmp(snap->oui, oui, 3) == 0, "oui is wrong: 0x%02x%02x%02x != 0x00601d",
                  snap->oui[0], snap->oui[1], snap->oui[2]);
    ck_assert_msg(snap->protocol_id == pid, "Protocol id error: %u != 1", snap->protocol_id);
    write_to_buf(log, MAXLINE, p);
    fp = fopen(PATH "snap.out", "r");
    ck_assert(fp);
    n = fread(out, sizeof(unsigned char), MAXLINE, fp);
    fclose(fp);
    ck_assert(n > 0);
    out[n-1] = '\0'; /* remove newline */
    ck_assert_msg(strcmp(log, out) == 0, "Text output is wrong");
}
END_TEST

Suite *decoder_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("decoder");
    tc_core = tcase_create("Core");
    suite_add_tcase(s, tc_core);
    tcase_add_unchecked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, snap_test);
    tcase_set_timeout(tc_core, 60);
    return s;
}
