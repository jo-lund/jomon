#ifndef PACKET_TLS_H
#define PACKET_TLS_H

#include <stdint.h>
#include "packet.h"

#define CHANGE_CIPHER_SPEC_TYPE 1
#define ENCRYPTED_HANDSHAKE_MESSAGE 0xff

enum content_type {
    TLS_CHANGE_CIPHER_SPEC = 20,
    TLS_ALERT = 21,
    TLS_HANDSHAKE = 22,
    TLS_APPLICATION_DATA = 23,
    TLS_HEARTBEAT = 24
};

enum version_type {
    SSL3_0 = 0x0300,
    TLS1_0 = 0x0301,
    TLS1_1 = 0x0302,
    TLS1_2 = 0x0303,
    TLS1_3 = 0x0304
};

enum handshake_type {
    TLS_HELLO_REQUEST = 0,
    TLS_CLIENT_HELLO = 1,
    TLS_SERVER_HELLO = 2,
    TLS_NEW_SESSION_TICKET = 4,
    TLS_END_OF_EARLY_DATA = 5,
    TLS_ENCRYPTED_EXTENSIONS = 8,
    TLS_CERTIFICATE = 11,
    TLS_SERVER_KEY_EXCHANGE = 12,
    TLS_CERTIFICATE_REQUEST = 13,
    TLS_SERVER_HELLO_DONE = 14,
    TLS_CERTIFICATE_VERIFY = 15,
    TLS_CLIENT_KEY_EXCHANGE = 16,
    TLS_FINISHED = 20,
    TLS_KEY_UPDATE = 24,
    TLS_MESSAGE_HASH = 254
};

enum alert_level {
    TLS_WARNING = 0,
    TLS_FATAL = 1
};

enum alert_description {
    TLS_CLOSE_NOTIFY = 0,
    TLS_UNEXPECTED_MESSAGE = 10,
    TLS_BAD_RECORD_MAC = 20,
    TLS_DECRYPTION_FAILED_RESERVED = 21,
    TLS_RECORD_OVERFLOW = 22,
    TLS_DECOMPRESSION_FAILURE = 30,
    TLS_HANDSHAKE_FAILURE = 40,
    TLS_NO_CERTIFICATE_RESERVED = 41,
    TLS_BAD_CERTIFICATE = 42,
    TLS_UNSUPPORTED_CERTIFICATE = 43,
    TLS_CERTIFICATE_REVOKED = 44,
    TLS_CERTIFICATE_EXPIRED = 45,
    TLS_CERTIFICATE_UNKNOWN = 46,
    TLS_ILLEGAL_PARAMETER = 47,
    TLS_UNKNOWN_CA = 48,
    TLS_ACCESS_DENIED = 49,
    TLS_DECODE_ERROR = 50,
    TLS_DECRYPT_ERROR = 51,
    TLS_XPORT_RESTRICTION_RESERVED = 60,
    TLS_PROTOCOL_VERSION = 70,
    TLS_INSUFFICIENT_SECURITY = 71,
    TLS_INTERNAL_ERROR = 80,
    TLS_USER_CANCELED = 90,
    TLS_NO_RENEGOTIATION = 100,
    TLS_UNSUPPORTED_EXTENSION = 110,
};

enum extension_type {
    SERVER_NAME = 0,                             /* RFC 6066 */
    MAX_FRAGMENT_LENGTH = 1,                     /* RFC 6066 */
    STATUS_REQUEST = 5,                          /* RFC 6066 */
    SUPPORTED_GROUPS = 10,                       /* RFC 8422, 7919 */
    SIGNATURE_ALGORITHMS = 13,                   /* RFC 8446 */
    USE_SRTP = 14,                               /* RFC 5764 */
    HEARTBEAT = 15,                              /* RFC 6520 */
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, /* RFC 7301 */
    SIGNED_CERTIFICATE_TIMESTAMP = 18,           /* RFC 6962 */
    CLIENT_CERTIFICATE_TYPE = 19,                /* RFC 7250 */
    SERVER_CERTIFICATE_TYPE = 20,                /* RFC 7250 */
    PADDING = 21,                                /* RFC 7685 */
    PRE_SHARED_KEY = 41,                         /* RFC 8446 */
    EARLY_DATA = 42,                             /* RFC 8446 */
    SUPPORTED_VERSIONS = 43,                     /* RFC 8446 */
    COOKIE = 44,                                 /* RFC 8446 */
    PSK_KEY_EXCHANGE_MODES = 45,                 /* RFC 8446 */
    CERTIFICATE_AUTHORITIES = 47,                /* RFC 8446 */
    OID_FILTERS = 48,                            /* RFC 8446 */
    POST_HANDSHAKE_AUTH = 49,                    /* RFC 8446 */
    SIGNATURE_ALGORITHMS_CERT = 50,              /* RFC 8446 */
    KEY_SHARE = 51
};

/* TLS 1.3 Signature algorithm extension types */
enum signature_scheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RSA_PKCS1_SHA256 = 0x0401,
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PKCS1_SHA512 = 0x0601,

    /* ECDSA algorithms */
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RSA_PSS_RSAE_SHA256 = 0x0804,
    RSA_PSS_RSAE_SHA384 = 0x0805,
    RSA_PSS_RSAE_SHA512 = 0x0806,

    /* EdDSA algorithms */
    ED25519 = 0x0807,
    ED448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RSA_PSS_PSS_SHA256 = 0x0809,
    RSA_PSS_PSS_SHA384 = 0x080a,
    RSA_PSS_PSS_SHA512 = 0x080b,

    /* Legacy algorithms */
    RSA_PKCS1_SHA1 = 0x0201,
    ECDSA_SHA1 = 0x0203
};

/* TLS 1.2 signature algorithm hash extension types */
enum hash_algorithm {
    MD5 = 1,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512
};

/* TLS 1.2 signature algorithm extension types */
enum signature_algorithm {
    ANONYMOUS,
    RSA,
    DSA,
    ECDSA
};

enum named_group {
    /* Elliptic Curve Groups (ECDHE) */
    SECP256R1 = 0x0017,
    SECP384R1 = 0x0018,
    SECP521R1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E,

    /* Finite Field Groups (DHE) */
    FFDHE2048 = 0x0100,
    FFDHE3072 = 0x0101,
    FFDHE4096 = 0x0102,
    FFDHE6144 = 0x0103,
    FFDHE8192 = 0x0104
};

struct tls_handshake {
    uint8_t type;
    uint8_t length[3];
    union {
        struct tls_handshake_client_hello *client_hello;
        struct tls_handshake_server_hello *server_hello;
    };
    struct tls_extension *ext;
};

/* tag-length-value encoded extension structures */
struct tls_extension {
    uint16_t type;
    uint16_t length;
    union {
        struct {
            uint16_t *versions;
            uint16_t length;
        } supported_versions;
        struct {
            uint8_t *ptr;
            uint16_t length;
        } cookie;
        struct {
            uint16_t *types;
            uint16_t length;
        } signature_algorithms;
        struct {
            uint16_t *named_group_list;
            uint16_t length;
        } supported_groups;
    };
    struct tls_extension *next;
};

struct tls_handshake_client_hello {
    /* In previous versions of TLS, the version field was used for
       version negotiation and represented the highest version number
       supported by the client. Experience has shown that many servers
       do not properly implement version negotiation, leading to "version
       intolerance" in which the server rejects an otherwise acceptable
       ClientHello with a version number higher than it supports.  In
       TLS 1.3, the client indicates its version preferences in the
       "supported_versions" extension and the legacy_version field MUST be
       set to 0x0303, which is the version number for TLS 1.2. TLS 1.3
       ClientHellos are identified as having a legacy_version of 0x0303 and
       a supported_versions extension present with 0x0304 as the highest
       version indicated therein. */
    uint16_t legacy_version;
    uint8_t random_bytes[32];
    uint8_t *session_id; /* between 0 and 32 bytes */
    uint8_t session_length;
    uint16_t *cipher_suites; /* between 2 and 2^16 - 2 */
    uint16_t cipher_length;
    uint8_t *compression_methods; /* not used for TLS 1.3 and should be set to 0 */
    uint8_t compression_length;
};

struct tls_handshake_server_hello {
    uint16_t legacy_version;
    uint8_t random_bytes[32];
    uint8_t *session_id; /* the contents of the client's session id */
    uint8_t session_length;
    /* the single cipher suite selected by the server from the list in
       ClientHello */
    uint16_t cipher_suite;
    /* Not used for TLS 1.3 and should be set to 0. For TLS 1.2 and below it is
       the single compression algorithm selected by the server from the list in
       ClientHello. */
    uint8_t compression_method;
};

struct tls_alert {
    uint8_t level;
    uint8_t description;
};

struct tls_change_cipher_spec {
    uint8_t type;
};

struct tls_info {
    uint8_t type;

    /* MUST be set to 0x0303 for all records generated by a TLS 1.3
       implementation other than an initial ClientHello where it MAY also be
       0x0301 for compatibility purposes. This field is deprecated and MUST be
       ignored for all purposes. */
    uint16_t version;
    uint16_t length;

    /* messages, except for handshake, are encrypted and possibly compressed */
    union {
        struct tls_handshake *handshake;
        struct tls_change_cipher_spec ccs;
        unsigned char *data;
    };
    struct tls_info *next;
};

char *get_tls_version(uint16_t version);
char *get_tls_type(uint8_t type);
char *get_tls_handshake_type(uint8_t type);
char *get_tls_cipher_suite(uint16_t suite);
char *get_signature_scheme(uint16_t type);
char *get_supported_group(uint16_t type);
void register_tls(void);
packet_error handle_tls(struct protocol_info *pinfo, unsigned char *buffer, int len,
                        struct packet_data *pdata);

#endif
