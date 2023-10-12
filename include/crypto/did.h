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
} ;

#endif /* INCLUDE_CRYPTO_DID_H_ */
