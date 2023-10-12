/*
 * vc.h
 *
 *  Created on: May 26, 2023
 *      Author: pirug
 */

#ifndef INCLUDE_CRYPTO_VC_H_
#define INCLUDE_CRYPTO_VC_H_

#include <openssl/types.h>

struct vc_st {
	/* VC fields */
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
};

struct vc_issuer_st {
	EVP_PKEY *pubkey;
	char *verificationMethod;
};

#endif /* INCLUDE_CRYPTO_VC_H_ */
