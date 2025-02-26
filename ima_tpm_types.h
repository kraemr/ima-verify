

#include <openssl/sha.h>
#include <openssl/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "test.h"
#if HAVE_OPENSSL_SHA_H
	//#include <openssl/sha.h> // DEPRECATED
	#include <openssl/evp.h>
#endif
typedef enum TPMVERSION {
	TPMVERSION1,
	TPMVERSION1_2,
	TPMVERSION2 // if version2 boot_aggregate will be sha256 instead of sha1 because its 'broken'
}TPMVERSION;

typedef enum HASHTYPE {
	TPM_SHA1,
	TPM_SHA256,
	TPM_SHA384,
	TPM_SHA512,
	TPM_SM3_256, // Chinese Standard ???
}HASHTYPE;


typedef struct TCG_PCR_EVENT_DIGEST2 {
	uint16_t algorithmId;
	uint8_t digest[EVP_MAX_MD_SIZE];
}TCG_PCR_EVENT_DIGEST2;

typedef struct TCG_PCR_DIGEST_LIST2 {
	uint32_t count;
	TCG_PCR_EVENT_DIGEST2* digestList;
}TCG_PCR_DIGEST_LIST2;

typedef struct TCG_PCR_EVENT2 {
	uint32_t pcrIndex;
	uint32_t eventType;
	TCG_PCR_DIGEST_LIST2 digests;
	uint32_t eventSize;
	uint8_t* eventData;
}TCG_PCR_EVENT2;


typedef struct SPEC_ID_EVENT {
	uint32_t platformClass;
	uint32_t specVersion; // actually 3bytes only 
	uint8_t reserved; // For Future use i guess
	uint32_t algoIdCount;
	uint16_t* algoIds;
}SPEC_ID_EVENT;