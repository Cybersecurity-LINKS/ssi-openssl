#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include "internal/provider.h"
#include <stdio.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/ssi.h>
#include <crypto/ssi.h>


DID_CTX *DID_CTX_new(OSSL_PROVIDER * provider){
    DID_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    
    if (ctx == NULL ) {
        printf("MALLOC ERROR\n");
        OPENSSL_free(ctx);
        //ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    }
    ctx->prov = provider;
    return ctx;
}

void DID_CTX_free(DID_CTX *ctx){
    if (ctx == NULL)
        return;
    OPENSSL_free(ctx);
}

DID_DOCUMENT* DID_DOCUMENT_new(void){
    DID_DOCUMENT* did_doc = OPENSSL_zalloc(sizeof(DID_DOCUMENT));
    if (did_doc == NULL)
        return NULL;
    did_doc->sig1 = NULL;
    did_doc->sig2 = NULL;
    did_doc->siglen1 = -1;
    did_doc->siglen2 = -1;
    did_doc->type1 = -1;
    did_doc->type2 = -1;
    return did_doc;
}

void DID_DOCUMENT_free(DID_DOCUMENT* did_doc){
    if(did_doc == NULL)
        return;
    if(did_doc->sig1 != NULL)
        OPENSSL_free(did_doc->sig1);
    if(did_doc->sig2 != NULL)
        OPENSSL_free(did_doc->sig2);
    OPENSSL_free(did_doc);
}

int DID_DOCUMENT_set(DID_DOCUMENT* did_doc, unsigned char* sig1, size_t len1, int type1, unsigned char* sig2, size_t len2, int type2){
    if(did_doc == NULL || sig1 == NULL || sig2 == NULL || len1 < 0 || len2 < 0 || type1 < 0 || type2 < 0)
        return 0;
    
    did_doc->sig1 = sig1;
    did_doc->sig2 = sig2;
    did_doc->siglen1 = len1;
    did_doc->siglen2 = len2;
    did_doc->type1 = type1;
    did_doc->type2 = type2;
    return 1;
}

int DID_DOCUMENT_set_auth_key(DID_DOCUMENT* did_doc, unsigned char* sig, size_t len, int type){
    if(did_doc == NULL || sig == NULL || len < 0 || type < 0 )
        return 0;
    if(did_doc->sig1 != NULL)
        OPENSSL_free(did_doc->sig1);
        did_doc->sig1 = sig;
    did_doc->siglen1 = len;
    did_doc->type1 = type;
    return 1;
}

int DID_DOCUMENT_set_assertion_key(DID_DOCUMENT* did_doc, unsigned char* sig, size_t len, int type){
    if(did_doc == NULL || sig == NULL || len < 0 || type < 0 )
        return 0;
    if(did_doc->sig2 != NULL)
        OPENSSL_free(did_doc->sig2);
        did_doc->sig2 = sig;
    did_doc->siglen2 = len;
    did_doc->type2 = type;
    return 1;
}

unsigned char* DID_DOCUMENT_get_auth_key(DID_DOCUMENT* did_doc){
    unsigned char* ptr = NULL;
    if(did_doc == NULL)
        return 0;
    ptr = OPENSSL_zalloc(did_doc->siglen1);
    memcpy(ptr,did_doc->sig1,did_doc->siglen1);
    return ptr;
}

unsigned char* DID_DOCUMENT_get_assertion_key(DID_DOCUMENT* did_doc){
    unsigned char* ptr = NULL;
    if(did_doc == NULL)
        return 0;
    ptr = OPENSSL_zalloc(did_doc->siglen2);
    memcpy(ptr,did_doc->sig2,did_doc->siglen2);
    return ptr;
}

int DID_fetch(OSSL_LIB_CTX *libctx, DID_CTX *ctx, const char *algorithm, const char *properties){
    const OSSL_ALGORITHM *map = NULL;
    const OSSL_DISPATCH *implementation = NULL;
    int n;
    (void) properties; //unused
    if(ctx == NULL)
        return 0;
    if(algorithm == NULL)
        algorithm = DID_OTT;
    map = ossl_provider_query_operation(ctx->prov, OSSL_OP_DID,&n);
    if(map == NULL){
        printf("MAP NULL\n");
        return 0;
    }
    for(n = 0; map[n].algorithm_names != NULL; n++){
        if(OPENSSL_strcasecmp(map[n].algorithm_names,algorithm) == 0){
            implementation = map[n].implementation;
            break;
        }
    }
    if(implementation == NULL){
        printf("Implementation not found\n");
        return 0;
    }
    for(n = 0; implementation[n].function_id != 0; n++){
        switch (implementation[n].function_id)
        {
        case OSSL_FUNC_DID_CREATE:
            ctx->didprovider_create =(void * (*)(void *, size_t,int , void *, size_t, int)) implementation[n].function;
            break;
        case OSSL_FUNC_DID_RESOLVE:
            ctx->didprovider_resolve =(int (*)(char *, DID_DOCUMENT *)) implementation[n].function;
        break;
        case OSSL_FUNC_DID_UPDATE:
            ctx->didprovider_update =(int (*)(char *,  void *, size_t,int , void *, size_t, int)) implementation[n].function;
        break;
        case OSSL_FUNC_DID_REVOKE:
            ctx->didprovider_revoke =(int (*)(char *)) implementation[n].function;
        break;
        default:
            printf("UNKNOWN FUNCTION ID\n");
            return 0;
            break;
        }
    }
    return 1;
}


char* DID_create(DID_CTX *ctx, DID_DOCUMENT* did_doc){
    if(ctx == NULL || ctx->didprovider_create == NULL)
        return NULL;
    if(did_doc->sig1 == NULL || did_doc->siglen1 < 0 || did_doc->sig2 == NULL || did_doc->siglen2 < 0)
        return NULL;
    char *new_did = ctx->didprovider_create(did_doc->sig1,did_doc->siglen1,did_doc->type1,did_doc->sig2,did_doc->siglen2,did_doc->type2);
    return new_did;
}

int DID_resolve(DID_CTX *ctx, char * did, DID_DOCUMENT* did_doc){
    if(ctx == NULL || ctx->didprovider_resolve == NULL || did == NULL)
        return DID_INTERNAL_ERROR;
    return ctx->didprovider_resolve(did, did_doc);
}

int DID_update(DID_CTX *ctx, DID_DOCUMENT* did_doc, char * did){
    if(ctx == NULL || ctx->didprovider_update == NULL || did == NULL || did_doc == NULL)
        return DID_INTERNAL_ERROR;
    if(did_doc->sig1 == NULL || did_doc->siglen1 < 0 || did_doc->sig2 == NULL || did_doc->siglen2 < 0)
        return DID_INTERNAL_ERROR;
    return ctx->didprovider_update(did,did_doc->sig1,did_doc->siglen1,did_doc->type1,did_doc->sig2,did_doc->siglen2,did_doc->type2);
}

int DID_revoke(DID_CTX *ctx,char * did){
    if(ctx == NULL || ctx->didprovider_revoke == NULL || did == NULL)
        return 0;
    return ctx->didprovider_revoke(did);
}
