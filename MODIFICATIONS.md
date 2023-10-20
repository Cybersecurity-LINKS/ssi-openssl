- `apps/s_client.c` and `apps/s_server.c` : added five new extensions
    - `-did`
    - `-did_key`
    - `-did_methods`
    - `-vc`
    - `-VCIfile`

## Crypto

- `evp_local_ssi.h`: created `EVP_VC_CTX` and `EVP_DID_CTX`
- `did_lib.c` and `did_meth.c`: implementation of `EVP_DID` methods
- `vc_lib.c` and `vc_meth.c`: implementation of `EVP_VC` methods

## Include/crypto

- `crypto/did.h`: 
- `crypto/vc.h`:
- `crypto/evp_ssi.h`: contains  `EVP_VC` and `EVP_DID` structures

## Include/openssl

- `core_dispatch.h` defines two new operations `OP_DID` and `OP_VC`
- `core_names.h` defines params for the for `OP_DID` and `OP_VC`
- `evp_ssi.h` declares `EVP_DID` and `EVP_VC` functions

## ssl

- `ssl_local.h`  
- `ssl_local_did.h` and `did.c`
- `ssl_local_vc.h`and `vc.c`

## ssl/statem

- `statem_local_did.h` and `statem_local_did.c` contains respectively declaration and definition of functions to construct and process the new extension/messages.

