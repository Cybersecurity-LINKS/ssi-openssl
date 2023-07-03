/*
 * did.h
 *
 *  Created on: Jul 3, 2023
 *      Author: pirug
 */

#ifndef INCLUDE_CRYPTO_DID_H_
#define INCLUDE_CRYPTO_DID_H_

#include <openssl/types.h>

typedef struct method {
	char *id;
	char *type;
	char *controller;
	char *pkey;
} method;

struct did_st {
	char *atContext;
	char *id;
	char *created;
	method *authentication;
	method *assertion;
} did;

#endif /* INCLUDE_CRYPTO_DID_H_ */
