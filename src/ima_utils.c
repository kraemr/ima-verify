#include "../inc/ima_utils.h"
#include <openssl/sha.h>
const char* MEASURENT_COUNT_PATH = "/sys/kernel/security/integrity/ima/measurements_count";
const char* VIOLATIONS_PATH = "/sys/kernel/security/integrity/ima/violations";
// TODO: Handle Endianness, on some systems pcr digest are big endian ...
// Expects a buffer thats atleast 4 bytes long
uint32_t castByteBufUint32(uint8_t* buf){
// Big endian
//	return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
// Little Endian
	return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
}

EVP_MD_CTX* initEVPContext(HASHTYPE hashType) {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if(mdctx == NULL) {
		return NULL;
	}
	int32_t initializationResult = 0;
	switch (hashType){
		case TPM_SHA1:  initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL); break;
		case TPM_SHA256: initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL); break;
		case TPM_SHA512: initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL); break;
        case TPM_SHA384:;break;
        case TPM_SM3_256:break;
    }
    return mdctx;
}


uint32_t getTpmHashLength(uint16_t algoId) {
	switch (algoId) {
		case TPM2_SHA1_ID: return SHA_DIGEST_LENGTH;break;
		case TPM2_SHA256_ID: return SHA256_DIGEST_LENGTH;break;
		case TPM2_SHA386_ID: return SHA384_DIGEST_LENGTH;break;
		case TPM2_SHA512_ID: return SHA512_DIGEST_LENGTH;break;
		case TPM2_SM3_256: return 0;break; // ?????? 
	}
	return 0;
}

void printAllIMAEntries(IMA_ENTRY* imaEntries,int n) {
	for(int i = 0; i< n;i++){
		IMA_ENTRY* temp = &imaEntries[i];
		//printf("Lengths pcr: %u tdl: %u tnl: %u tfl: %u\n",temp->PCR_INDEX,temp->TEMPLATE_DATA_LEN,temp->TEMPLATE_NAME_LEN,temp->TEMPLATE_FILENAME_LEN);
		displayDigest(temp->PCR_VALUE,SHA256_DIGEST_LENGTH);
		displayDigest(temp->HASH,temp->HASH_LEN-8);
		printf("%s\n\n",temp->TEMPLATE_FILENAME);
	}
}

void freeIMAEntry(IMA_ENTRY* entry){
	free(entry->HASH);
	free(entry->PCR_VALUE);
	free(entry->TEMPLATE_NAME);
	free(entry->TEMPLATE_FILENAME);
}

void freeIMAEntries(IMA_ENTRY* imaEntries,int n) {
	for(int i = 0; i < n; i++ ){
		freeIMAEntry(&imaEntries[i]);
	}
}



uint32_t getMeasurementCount() {
    FILE * fp = fopen(MEASURENT_COUNT_PATH,"rb");
    uint32_t count=0;
    if(fp == NULL){
        return count;
    }
    fread(&count,4,1,fp);
    return count;
}

uint32_t getViolationsCount() {
    FILE * fp = fopen(VIOLATIONS_PATH,"rb");
    uint32_t count=0;
    if(fp == NULL){
        return count;
    }
    fread(&count,4,1,fp);
    return count;
}

void displayDigest(uint8_t *pcr, int32_t n)
{
	for (int32_t i = 0; i < n; i++)
		printf("%x", pcr[i] );
	printf("\n");
}

void displayN(uint8_t *pcr, int32_t n)
{
	for (int32_t i = 0; i < n; i++)
		printf("%c ", pcr[i] );
	printf("\n");
}


TPMVERSION determineTPMVersion() {
	// find out how to check for tpm version TODO
	return TPMVERSION2;
}
