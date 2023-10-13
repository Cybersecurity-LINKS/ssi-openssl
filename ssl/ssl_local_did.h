/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
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

int tls1_process_did_methods(SSL *s);

#endif /* SSL_SSL_LOCAL_DID_H_ */
