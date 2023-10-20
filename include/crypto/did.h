/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
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
