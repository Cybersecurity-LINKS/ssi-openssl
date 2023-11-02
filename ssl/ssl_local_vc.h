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

#ifndef SSL_SSL_LOCAL_VC_H_
#define SSL_SSL_LOCAL_VC_H_

#include <openssl/ssl.h>
#include <openssl/types.h>

VC *ssl_vc_new(void);

VC* ssl_vc_dup(VC *vc);

VC_ISSUER* ssl_vc_issuers_dup(VC_ISSUER *issuers, size_t issuers_num);

__owur int send_ssi_request(SSL *s);

#endif /* SSL_SSL_LOCAL_VC_H_ */
