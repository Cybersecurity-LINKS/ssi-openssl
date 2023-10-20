/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#ifndef INCLUDE_CRYPTO_VC_H_
#define INCLUDE_CRYPTO_VC_H_

#include <openssl/types.h>

struct vc_st {
	char *atContext;
	char *id;
	char *type;
	char *issuer;
	char *issuanceDate;
	char *expirationDate;
	char *credentialSubject;
	char *proofType;
	char *proofCreated;
	char *proofPurpose;
	char *verificationMethod;
	char *proofValue;
} /* VC */;

struct vc_issuer_st {
	EVP_PKEY *pubkey;
	char *verificationMethod;
} /* VC_ISSUER */;

#endif /* INCLUDE_CRYPTO_VC_H_ */
