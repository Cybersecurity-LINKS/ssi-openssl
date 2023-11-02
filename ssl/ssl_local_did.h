/*
 * Copyright 2023 Fondazione Links.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.	
 *
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

__owur int tls13_set_shared_didmethods(SSL *s);

__owur void tls13_set_server_auth_method(SSL *s);

__owur int ssl_has_did(const SSL *s, int idx);

int tls_choose_did_sigalg(SSL *s, int fatalerrs);

DID *ssl_did_new(void);

DID *ssl_did_dup(DID *did);

int tls1_process_did_methods(SSL *s);

#endif /* SSL_SSL_LOCAL_DID_H_ */
