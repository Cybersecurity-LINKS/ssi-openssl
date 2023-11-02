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


#ifndef INCLUDE_CRYPTO_DID_H_
#define INCLUDE_CRYPTO_DID_H_

#include <openssl/types.h>

typedef struct method {
	char *id;
	char *type;
	char *controller;
	char *pkey_pem;
	EVP_PKEY *pkey;
} method;

struct did_doc_st {
	char *atContext;
	char *id;
	char *created;
	method authentication;
	method assertion;
} /* DID_DOC */;

#endif /* INCLUDE_CRYPTO_DID_H_ */
