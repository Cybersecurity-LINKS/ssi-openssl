/*
 * ssl_local_vc.h
 *
 *  Created on: Jun 1, 2023
 *      Author: pirug
 */

#ifndef SSL_SSL_LOCAL_VC_H_
#define SSL_SSL_LOCAL_VC_H_

#include <openssl/ssl.h>
#include <openssl/types.h>

VC *ssl_vc_new(void);

VC* ssl_vc_dup(VC *vc);

VC_ISSUER* ssl_vc_issuers_dup(VC_ISSUER *issuers, size_t issuers_num);

__owur int send_vc_request(SSL *s);

#endif /* SSL_SSL_LOCAL_VC_H_ */
