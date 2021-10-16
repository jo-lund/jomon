#include <assert.h>
#include "packet_tls.h"
#include "../monitor.h"

#define TLS_MAX_SIZE 16384
#define TLS_HEADER_SIZE 5
#define TLS_HANDSHAKE_HEADER 4
#define TLS_MIN_CLIENT_HELLO 41

static struct uint_string cipher_suite[] = {
    { 0x0000, "TLS_NULL_WITH_NULL_NULL" },
    { 0x0001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x0002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x0004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x0005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000C, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000F, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x0018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x001A, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x001E, "TLS_KRB5_WITH_DES_CBC_SHA" },
    { 0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
    { 0x0020, "TLS_KRB5_WITH_RC4_128_SHA" },
    { 0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
    { 0x0022, "TLS_KRB5_WITH_DES_CBC_MD5" },
    { 0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
    { 0x0024, "TLS_KRB5_WITH_RC4_128_MD5" },
    { 0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
    { 0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
    { 0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
    { 0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
    { 0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
    { 0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
    { 0x002C, "TLS_PSK_WITH_NULL_SHA" },
    { 0x002D, "TLS_DHE_PSK_WITH_NULL_SHA" },
    { 0x002E, "TLS_RSA_PSK_WITH_NULL_SHA" },
    { 0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x003B, "TLS_RSA_WITH_NULL_SHA256" },
    { 0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
    { 0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
    { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x008A, "TLS_PSK_WITH_RC4_128_SHA" },
    { 0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA" },
    { 0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA" },
    { 0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
    { 0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
    { 0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
    { 0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
    { 0x0096, "TLS_RSA_WITH_SEED_CBC_SHA" },
    { 0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
    { 0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
    { 0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
    { 0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
    { 0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
    { 0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
    { 0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
    { 0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B0, "TLS_PSK_WITH_NULL_SHA256" },
    { 0x00B1, "TLS_PSK_WITH_NULL_SHA384" },
    { 0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
    { 0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
    { 0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
    { 0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384" },
    { 0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
    { 0x1301, "TLS_AES_128_GCM_SHA256" },
    { 0x1302, "TLS_AES_256_GCM_SHA384" },
    { 0x1303, "TLS_CHACHA20_POLY1305_SHA256" },
    { 0x1304, "TLS_AES_128_CCM_SHA256" },
    { 0x1305, "TLS_AES_128_CCM_8_SHA256" },
    { 0x5600, "TLS_FALLBACK_SCSV" },
    { 0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
    { 0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
    { 0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA" },
    { 0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
    { 0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
    { 0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
    { 0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
    { 0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
    { 0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0xC015, "TLS_ECDH_anon_WITH_NULL_SHA" },
    { 0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
    { 0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
    { 0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
    { 0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
    { 0xC01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
    { 0xC01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
    { 0xC020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
    { 0xC021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
    { 0xC022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
    { 0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
    { 0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
    { 0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
    { 0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
    { 0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
    { 0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
    { 0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },
    { 0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256" },
    { 0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384" },
    { 0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256" },
    { 0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384" },
    { 0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256" },
    { 0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384" },
    { 0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256" },
    { 0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384" },
    { 0xC058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256" },
    { 0xC059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC06A, "TLS_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06B, "TLS_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC06C, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06D, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC06E, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06F, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC07E, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07F, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08E, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08F, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC09A, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC09B, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC09C, "TLS_RSA_WITH_AES_128_CCM" },
    { 0xC09D, "TLS_RSA_WITH_AES_256_CCM" },
    { 0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM" },
    { 0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM" },
    { 0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8" },
    { 0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8" },
    { 0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8" },
    { 0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8" },
    { 0xC0A4, "TLS_PSK_WITH_AES_128_CCM" },
    { 0xC0A5, "TLS_PSK_WITH_AES_256_CCM" },
    { 0xC0A6, "TLS_DHE_PSK_WITH_AES_128_CCM" },
    { 0xC0A7, "TLS_DHE_PSK_WITH_AES_256_CCM" },
    { 0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8" },
    { 0xC0A9, "TLS_PSK_WITH_AES_256_CCM_8" },
    { 0xC0AA, "TLS_PSK_DHE_WITH_AES_128_CCM_8" },
    { 0xC0AB, "TLS_PSK_DHE_WITH_AES_256_CCM_8" },
    { 0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM" },
    { 0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM" },
    { 0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" },
    { 0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8" },
    { 0xC0B0, "TLS_ECCPWD_WITH_AES_128_GCM_SHA256" },
    { 0xC0B1, "TLS_ECCPWD_WITH_AES_256_GCM_SHA384" },
    { 0xC0B2, "TLS_ECCPWD_WITH_AES_128_CCM_SHA256" },
    { 0xC0B3, "TLS_ECCPWD_WITH_AES_256_CCM_SHA384" },
    { 0xC0B4, "TLS_SHA256_SHA256" },
    { 0xC0B5, "TLS_SHA384_SHA384" },
    { 0xC100, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC" },
    { 0xC101, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC" },
    { 0xC102, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT" },
    { 0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xD001, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0xD002, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0xD003, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256" },
    { 0xD005, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256" }
};

enum tls_state {
    NORMAL,
    CCS
};

extern void print_tls(char *buf, int n, void *data);
extern void add_tls_information(void *widget, void *subwidget, void *data);
static packet_error parse_handshake(unsigned char **buf, uint16_t n,
                                    struct tls_info *tls);
static packet_error parse_client_hello(unsigned char **buf, uint16_t n,
                                       struct tls_handshake *handshake);
static packet_error parse_server_hello(unsigned char **buf, uint16_t len,
                                       struct tls_handshake *handshake);
static enum pool prev;

static struct protocol_info tls_prot = {
    .short_name = "TLS",
    .long_name = "Transport Layer Security",
    .decode = handle_tls,
    .print_pdu = print_tls,
    .add_pdu = add_tls_information
};

void register_tls()
{
    register_protocol(&tls_prot, PORT, HTTPS);
    register_protocol(&tls_prot, PORT, IMAPS);
    register_protocol(&tls_prot, PORT, SMTPS);
}

packet_error handle_tls(struct protocol_info *pinfo, unsigned char *buf, int n,
                        struct packet_data *pdata)
{
    if (n < TLS_HEADER_SIZE || n > TLS_MAX_SIZE) return DECODE_ERR;

    uint16_t data_len = 0;
    struct tls_info **pptr;
    enum tls_state state = NORMAL;
    int i = 0;
    struct tls_info *tls;

    pptr = &tls;
    while (data_len < n) {
        uint16_t record_len;

        *pptr = mempool_alloc(sizeof(struct tls_info));
        (*pptr)->next = NULL;
        (*pptr)->type = buf[0];
        (*pptr)->version = get_uint16be(buf + 1);
        (*pptr)->length = get_uint16be(buf + 3);
        if ((*pptr)->length > n) {
             /* TODO: Need to support TCP reassembly */
            if (i == 0) {
                return UNK_PROTOCOL;
            } else {
                mempool_free(*pptr);
                *pptr = NULL;
                goto done;
            }
        }
        record_len = (*pptr)->length;
        data_len += record_len + TLS_HEADER_SIZE;
        buf += TLS_HEADER_SIZE;
        switch ((*pptr)->type) {
        case TLS_CHANGE_CIPHER_SPEC:
            (*pptr)->ccs.type = buf[0];
            buf += record_len;
            state = CCS;
            break;
        case TLS_ALERT:
        case TLS_APPLICATION_DATA:
        case TLS_HEARTBEAT:
            buf += record_len;
            break;
        case TLS_HANDSHAKE:
            if (state == CCS) {
                (*pptr)->handshake = mempool_alloc(sizeof(struct tls_handshake));
                (*pptr)->handshake->type = ENCRYPTED_HANDSHAKE_MESSAGE;
                buf += record_len;
            } else {
                // BUG: Need to handle this properly
                if (parse_handshake(&buf, record_len, *pptr) != NO_ERR)
                    return DECODE_ERR;
            }
            break;
        default:
            buf += record_len;
            break;
        }
        pptr = &(*pptr)->next;
        i++;
    }

done:
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    pdata->data = tls;
    pdata->len = n;
    return NO_ERR;
}

static packet_error parse_handshake(unsigned char **buf, uint16_t len, struct tls_info *tls)
{
    if (len < TLS_HANDSHAKE_HEADER) return DECODE_ERR;

    packet_error err = NO_ERR;
    unsigned char *ptr = *buf;

    tls->handshake = mempool_alloc(sizeof(struct tls_handshake));
    tls->handshake->type = ptr[0];
    memcpy(tls->handshake->length, ptr + 1, 3);
    ptr += 4;
    len -= 4;
    switch (tls->handshake->type) {
    case TLS_CLIENT_HELLO:
        err = parse_client_hello(&ptr, len, tls->handshake);
        break;
    case TLS_SERVER_HELLO:
        err = parse_server_hello(&ptr, len, tls->handshake);
        break;
    case TLS_HELLO_REQUEST:
        break;
    case TLS_ENCRYPTED_EXTENSIONS:
    default:
        ptr += len;
        break;
    }
    *buf = ptr;
    return err;
}

static packet_error parse_client_hello(unsigned char **buf, uint16_t len,
                                       struct tls_handshake *handshake)
{
    if (len < TLS_MIN_CLIENT_HELLO) return DECODE_ERR;

    unsigned char *ptr = *buf;

    handshake->client_hello = mempool_alloc(sizeof(struct tls_handshake_client_hello));
    handshake->client_hello->legacy_version = get_uint16be(ptr);
    memcpy(handshake->client_hello->random_bytes, ptr + 2, 32);
    ptr += 34;
    len -= 34;
    if ((handshake->client_hello->session_length = ptr[0]) > len) {
        return DECODE_ERR;
    }
    handshake->client_hello->session_id =
        mempool_copy(ptr + 1, handshake->client_hello->session_length);
    ptr += handshake->client_hello->session_length + 1;
    len = len - (handshake->client_hello->session_length + 1);
    if ((handshake->client_hello->cipher_length = get_uint16be(ptr)) > len) {
        return DECODE_ERR;
    }
    handshake->client_hello->cipher_suites =
        mempool_copy(ptr + 2, handshake->client_hello->cipher_length);
    ptr += handshake->client_hello->cipher_length + 2;
    len = len - (handshake->client_hello->cipher_length + 2);
    if ((handshake->client_hello->compression_length = ptr[0]) > len) {
        return DECODE_ERR;
    }
    if (handshake->client_hello->compression_length == 0) {
        handshake->client_hello->compression_methods = NULL;
        ptr++;
        len--;
    } else {
        handshake->client_hello->compression_methods =
            mempool_copy(ptr + 1, handshake->client_hello->compression_length);
        ptr += handshake->client_hello->compression_length + 1;
        len = len - (handshake->client_hello->compression_length + 1);
    }
    handshake->client_hello->data = mempool_copy(ptr, len);
    handshake->client_hello->data_len = len;
    ptr += len;
    *buf = ptr;
    return NO_ERR;
}

static packet_error parse_server_hello(unsigned char **buf, uint16_t len,
                                       struct tls_handshake *handshake)
{
    if (len < TLS_MIN_CLIENT_HELLO) return DECODE_ERR;

    unsigned char *ptr = *buf;

    handshake->server_hello = mempool_alloc(sizeof(struct tls_handshake_server_hello));
    handshake->server_hello->legacy_version = get_uint16be(ptr);
    memcpy(handshake->server_hello->random_bytes, ptr + 2, 32);
    ptr += 34;
    len -= 34;
    if ((handshake->server_hello->session_length = ptr[0]) > len) {
        return DECODE_ERR;
    }
    handshake->server_hello->session_id =
        mempool_copy(ptr + 1, handshake->server_hello->session_length);
    ptr += handshake->server_hello->session_length + 1;
    len = len - (handshake->server_hello->session_length + 1);
    handshake->server_hello->cipher_suite = get_uint16be(ptr);
    ptr += 2;
    len -= 2;
    handshake->server_hello->compression_method = ptr[0];
    ptr++;
    len--;
    handshake->server_hello->data = mempool_copy(ptr, len);
    handshake->server_hello->data_len = len;
    ptr += len;
    *buf = ptr;
    return NO_ERR;
}

list_t *parse_tls_extensions(unsigned char *data, uint16_t len)
{
    allocator_t alloc = {
        .alloc = mempool_alloc,
        .dealloc = NULL
    };
    list_t *extensions;
    int length = len;

    prev = mempool_set(POOL_SHORT);
    extensions = list_init(&alloc);
    length -= 2;
    data += 2;
    while (length > 0) {
        struct tls_extension *ext = mempool_alloc(sizeof(struct tls_extension));

        ext->type = get_uint16be(data);
        ext->length = get_uint16be(data + 2);
        data += 4;
        length -= 4;
        switch (ext->type) {
        case SERVER_NAME:
        case MAX_FRAGMENT_LENGTH:
        case STATUS_REQUEST:
            break;
        case SUPPORTED_GROUPS:
            if (ext->length < length) {
                ext->supported_groups.named_group_list = mempool_copy(data, ext->length);
                ext->supported_groups.length = ext->length;
                list_push_back(extensions, ext);
            }
            break;
        case SIGNATURE_ALGORITHMS:
            if (ext->length < length) {
                ext->signature_algorithms.types = mempool_copy(data, ext->length);
                ext->signature_algorithms.length = ext->length;
                list_push_back(extensions, ext);
            }
            break;
        case USE_SRTP:
        case HEARTBEAT:
        case APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
        case SIGNED_CERTIFICATE_TIMESTAMP:
        case CLIENT_CERTIFICATE_TYPE:
        case SERVER_CERTIFICATE_TYPE:
        case PADDING:
        case PRE_SHARED_KEY:
        case EARLY_DATA:
            break;
        case SUPPORTED_VERSIONS:
            if (ext->length < length) {
                ext->supported_versions.versions = mempool_copy(data, ext->length);
                ext->supported_versions.length = ext->length;
                list_push_back(extensions, ext);
            }
            break;
        case COOKIE:
            if (ext->length < length) {
                ext->cookie.ptr = mempool_copy(data, ext->length);
                ext->cookie.length = ext->length;
                list_push_back(extensions, ext);
            }
            break;
        case PSK_KEY_EXCHANGE_MODES:
        case CERTIFICATE_AUTHORITIES:
        case OID_FILTERS:
        case POST_HANDSHAKE_AUTH:
        case SIGNATURE_ALGORITHMS_CERT:
        case KEY_SHARE:
        default:
            break;
        }
        length -= ext->length;
        data += ext->length;
    }
    return extensions;
}

void free_tls_extensions(list_t *extensions)
{
    mempool_free(extensions);
    mempool_set(prev);
}

char *get_tls_version(uint16_t version)
{
    switch (version) {
    case SSL3_0:
        return "SSLv3.0";
    case TLS1_0:
        return "TLSv1.0";
    case TLS1_1:
        return "TLSv1.1";
    case TLS1_2:
        return "TLSv1.2";
    case TLS1_3:
        return "TLSv1.3";
    default:
        return NULL;
    }
}

char *get_tls_type(uint8_t type)
{
    switch (type) {
    case TLS_CHANGE_CIPHER_SPEC:
        return "Change Cipher Spec";
    case TLS_ALERT:
        return "Alert";
    case TLS_HANDSHAKE:
        return "Handshake";
    case TLS_APPLICATION_DATA:
        return "Application Data";
    case TLS_HEARTBEAT:
        return "Heartbeat";
    default:
        return NULL;
    }
}

char *get_tls_handshake_type(uint8_t type)
{
    switch (type) {
    case TLS_HELLO_REQUEST:
        return "Hello Request";
    case TLS_CLIENT_HELLO:
        return "Client Hello";
    case TLS_SERVER_HELLO:
        return "Server Hello";
    case TLS_NEW_SESSION_TICKET:
        return "New Session Ticket";
    case TLS_END_OF_EARLY_DATA:
        return "End of Early Data";
    case TLS_ENCRYPTED_EXTENSIONS:
        return "Encrypted Extensions";
    case TLS_CERTIFICATE:
        return "Certificate";
    case TLS_SERVER_KEY_EXCHANGE:
        return "Server Key Exchange";
    case TLS_CERTIFICATE_REQUEST:
        return "Certificate Request";
    case TLS_SERVER_HELLO_DONE:
        return "Server Hello Done";
    case TLS_CERTIFICATE_VERIFY:
        return "Certificate Verify";
    case TLS_CLIENT_KEY_EXCHANGE:
        return "Client Key Exchange";
    case TLS_FINISHED:
        return "Finished";
    case TLS_KEY_UPDATE:
        return "Key Update";
    case TLS_MESSAGE_HASH:
        return "Message Hash";
    case ENCRYPTED_HANDSHAKE_MESSAGE:
        return "Encrypted Handshake Message";
    default:
        return NULL;
    }
}

char *get_tls_cipher_suite(uint16_t suite)
{
    struct uint_string key = { .val = suite };
    struct uint_string *res;

    res = bsearch(&key, cipher_suite, ARRAY_SIZE(cipher_suite),
                  sizeof(struct uint_string), cmp_val);
    return res ? res->str : "Unknown";
}

char *get_signature_scheme(uint16_t type)
{
    switch (type) {
    case RSA_PKCS1_SHA256:
        return "rsa_pkcs1_sha256";
    case RSA_PKCS1_SHA384:
        return "rsa_pkcs1_sha384";
    case RSA_PKCS1_SHA512:
        return "rsa_pkcs1_sha512";
    case ECDSA_SECP256R1_SHA256:
        return "ecdsa_secp256r1_sha256";
    case ECDSA_SECP384R1_SHA384:
        return "ecdsa_secp384r1_sha384";
    case ECDSA_SECP521R1_SHA512:
        return "ecdsa_secp521r1_sha512";
    case RSA_PSS_RSAE_SHA256:
        return "rsa_pss_rsae_sha256";
    case RSA_PSS_RSAE_SHA384:
        return "rsa_pss_rsae_sha384";
    case RSA_PSS_RSAE_SHA512:
        return "rsa_pss_rsae_sha512";
    case ED25519:
        return "ed25519";
    case ED448:
        return "ed448";
    case RSA_PSS_PSS_SHA256:
        return "rsa_pss_pss_sha256";
    case RSA_PSS_PSS_SHA384:
        return "rsa_pss_pss_sha384";
    case RSA_PSS_PSS_SHA512:
        return "rsa_pss_pss_sha512";
    case RSA_PKCS1_SHA1:
        return "rsa_pkcs1_sha1";
    case ECDSA_SHA1:
        return "ecdsa_sha1";
    default:
        return NULL;
    }
}

char *get_supported_group(uint16_t type)
{
    switch (type) {
    case SECP256R1:
        return "secp256r1";
    case SECP384R1:
        return "secp384r1";
    case SECP521R1:
        return "secp521r1";
    case X25519:
        return "x25519";
    case X448:
        return "x448";
    case FFDHE2048:
        return "ffdhe2048";
    case FFDHE3072:
        return "ffdhe3072";
    case FFDHE4096:
        return "ffdhe4096";
    case FFDHE6144:
        return "ffdhe6144";
    case FFDHE8192:
        return "ffdhe8192";
    default:
        return NULL;
    }
}
