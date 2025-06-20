#include <check.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include "mempool.h"
#include "jomon.h"
#include "file.h"
#include "decoder/packet.h"
#include "decoder/decoder.h"
#include "decoder/host_analyzer.h"
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

static void test_protocol_text(char *file)
{
    char log[MAXLINE];
    char out[MAXLINE];
    int n;
    FILE *fp;

    pkt2text(log, MAXLINE, p);
    fp = fopen(file, "r");
    ck_assert(fp);
    n = fread(out, sizeof(char), MAXLINE, fp);
    fclose(fp);
    ck_assert(n > 0);
    out[n-1] = '\0'; /* remove newline */
    ck_assert_msg(strcmp(log, out) == 0, "Text output is wrong:\n\"%s\"\n\"%s\"", log, out);
}

static void setup(void)
{
    mempool_init();
    decoder_init();
    host_analyzer_init();
    handle = iface_handle_create(buf, SNAPLEN, handle_packet);
}

static void teardown(void)
{
    decoder_exit();
    host_analyzer_free();
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

START_TEST(tcp_opt_err_test)
{
    struct packet_data *pdata;

    read_file(PATH "tcp_opt_err.pcap");
    pdata = get_pdata(p, IPPROTO_TCP);
    ck_assert_msg(pdata, "Not a TCP packet");
    ck_assert(strcmp(pdata->error, "TCP options error") == 0);
}
END_TEST

START_TEST(snap_test)
{
    unsigned char oui[3] = { 0, 0x60, 0x1d };
    uint16_t pid = 1;
    struct packet_data *pdata;
    struct snap_info *snap;

    read_file(PATH "snap.pcap");
    pdata = get_pdata(p, ETH_802_SNAP);
    ck_assert_msg(pdata, "Not a SNAP packet");
    snap = pdata->data;
    ck_assert(snap);
    ck_assert_msg(memcmp(snap->oui, oui, 3) == 0, "oui is wrong: 0x%02x%02x%02x != 0x00601d",
                  snap->oui[0], snap->oui[1], snap->oui[2]);
    ck_assert_msg(snap->protocol_id == pid, "Protocol id error: %u != 1", snap->protocol_id);
    test_protocol_text(PATH "snap.out");
}
END_TEST

START_TEST(snmp_test)
{
    struct packet_data *pdata;
    struct snmp_info *snmp;
    const node_t *n;
    uint8_t version = 0;
    char *community = "public";
    uint8_t pdu_type = SNMP_GET_RESPONSE;
    uint32_t request_id = 76656815;
    uint32_t error_status = 0;
    uint32_t error_index = 0;
    char *name[3] = {
        "1.3.6.1.2.1.2.2.1.10.46",
        "1.3.6.1.2.1.2.2.1.16.46",
        "1.3.6.1.2.1.1.3.0"
    };
    int64_t value[3] = { 49644710, 4188063068, 32801169 };
    int i = 0;
    struct snmp_varbind *var;

    read_file(PATH "snmp.pcap");
    pdata = get_pdata(p, SNMP);
    ck_assert_msg(pdata, "Not an SNMP packet");
    snmp = pdata->data;
    ck_assert(snmp);
    ck_assert_msg(snmp->version == version, "SNMP version error: %u != %u",
                  snmp->version, version);
    ck_assert_msg(strcmp(snmp->community, community) == 0, "SNMP community error: %s != %s",
                  snmp->community, community);
    ck_assert_msg(snmp->pdu_type == pdu_type, "SNMP PDU type error: %u != %u",
                  snmp->pdu_type, pdu_type);
    ck_assert_msg(snmp->pdu->request_id == request_id, "SNMP request id error: %u != %u",
                  snmp->pdu->request_id, request_id);
    ck_assert_msg(snmp->pdu->error_status == error_status, "SNMP error status error: %u != %u",
                  snmp->pdu->error_status, error_status);
    ck_assert_msg(snmp->pdu->error_index == error_index, "SNMP error index error: %u != %u",
                  snmp->pdu->error_index, error_index);
    DLIST_FOREACH(snmp->pdu->varbind_list, n) {
        var = list_data(n);
        ck_assert_msg(var->type == SNMP_INTEGER_TAG, "SNMP object type error: %u != %u",
                      var->type, SNMP_INTEGER_TAG);
        ck_assert_msg(strcmp(var->object_name, name[i]) == 0, "SNMP object name error: %s != %s",
                      var->object_name, name[i]);
        ck_assert_msg(var->object_syntax.ival == value[i], "SNMP object value error: %ld != %ld",
                      var->object_syntax.ival, value[i]);
        i++;
    }
    test_protocol_text(PATH "snmp.out");
}
END_TEST

START_TEST(nbns_test)
{
    struct packet_data *pdata;
    struct nbns_info *nbns;
    int records = 0;

    read_file(PATH "nbns.pcap");
    pdata = get_pdata(p, NBNS);
    ck_assert_msg(pdata, "Not an NBNS packet");
    ck_assert_msg(pdata->error == NULL, "Failed decoding packet: %s", pdata->error);
    nbns = pdata->data;
    ck_assert(nbns);

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += nbns->section_count[i];
    }
    ck_assert(records == 1);
    ck_assert_msg(strcmp(nbns->record[0].rrname, "JEREMIAHS-MBP<00>") == 0,
                  "NetBIOS name is wrong: \'%s\' != \'JEREMIAHS-MBP<00>\'", nbns->record[0].rrname);
    ck_assert(nbns->record[0].rrtype == NBNS_NB);
    test_protocol_text(PATH "nbns.out");
}

Suite *decoder_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("decoder");
    tc_core = tcase_create("Core");
    suite_add_tcase(s, tc_core);
    tcase_add_unchecked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, snap_test);
    tcase_add_test(tc_core, snmp_test);
    tcase_add_test(tc_core, tcp_opt_err_test);
    tcase_add_test(tc_core, nbns_test);
    tcase_set_timeout(tc_core, 60);
    return s;
}
