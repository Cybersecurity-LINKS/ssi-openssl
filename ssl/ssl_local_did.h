/*
 * did_local.h
 *
 *  Created on: Oct 12, 2022
 *      Author: leonardo
 */

#ifndef SSL_SSL_LOCAL_DID_H_
#define SSL_SSL_LOCAL_DID_H_

#include "ssl_local.h"
#include <openssl/ssl.h>

/* supported did methods values */
#define TLSEXT_DID_METHOD_ott			0x01
#define TLSEXT_DID_METHOD_btc			0x02
#define TLSEXT_DID_METHOD_eth 			0x03

/* Structure containing table entry of values associated with the
supported did methods extension */

typedef struct didmethod_lookup_st {
    /* TLS 1.3 did method name */
    const char *name;
    /* Raw value used in extension */
    uint8_t didmethod;
} DIDMETHOD_LOOKUP;

__owur int tls13_set_server_did_methods(SSL *s);

__owur int ssl_has_did(const SSL *s, int idx);

int tls_choose_did_sigalg(SSL *s, int fatalerrs);

DID *ssl_did_new(void);

DID *ssl_did_dup(DID *did);

__owur int send_did_request(SSL *s);

int tls1_process_supported_did_methods(SSL *s);

#endif /* SSL_SSL_LOCAL_DID_H_ */
