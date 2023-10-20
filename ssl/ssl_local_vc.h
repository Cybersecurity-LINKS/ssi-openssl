/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef SSL_SSL_LOCAL_VC_H_
#define SSL_SSL_LOCAL_VC_H_

#include <openssl/ssl.h>
#include <openssl/types.h>

VC *ssl_vc_new(void);

VC* ssl_vc_dup(VC *vc);

VC_ISSUER* ssl_vc_issuers_dup(VC_ISSUER *issuers, size_t issuers_num);

__owur int send_ssi_request(SSL *s);

#endif /* SSL_SSL_LOCAL_VC_H_ */
