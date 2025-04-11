#include "../inc/ima_utils.h"
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <uchar.h>
const char* MEASURENT_COUNT_PATH = "/sys/kernel/security/integrity/ima/measurements_count";
const char* VIOLATIONS_PATH = "/sys/kernel/security/integrity/ima/violations";

uint64_t getFileSize(FILE * fp){
	uint64_t originalPosition = ftell(fp);
	fseek(fp,0,SEEK_END);
	uint64_t t = ftell(fp);
	fseek(fp,originalPosition,SEEK_SET);
	return t;
}


// TODO: Handle Endianness, on some systems pcr digest are big endian ...
// Expects a buffer thats atleast 4 bytes long
uint32_t castByteBufUint32(uint8_t* buf){
// Big endian
//	return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
// Little Endian
	return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
}

int32_t compute_hash(uint8_t* input,uint32_t len, uint8_t output[EVP_MAX_MD_SIZE], uint32_t *output_length,uint16_t algoId) {
    EVP_MD_CTX *mdctx = initEVPContext(algoId);
    if (mdctx == NULL) {
        printf("Error initializing EVP_MD_CTX\n");
        return 0;
    }
    if (EVP_DigestUpdate(mdctx, input, len) != 1) {
        printf("Digest update failed\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (EVP_DigestFinal_ex(mdctx, output, output_length) != 1) {
        printf("Digest finalization failed\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    EVP_MD_CTX_free(mdctx);
	return 1;
}

EVP_MD_CTX* initEVPContext(uint16_t hashType) {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if(mdctx == NULL) {
		return NULL;
	}
//	printf(" initEVPContext for HashType: %u\n",hashType);
	int32_t initializationResult = 0;
	switch (hashType){
		case TPM2_SHA1_ID:   initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha1(),   NULL); break;
		case TPM2_SHA256_ID: initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL); break;
		case TPM2_SHA512_ID: initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL); break;
        case TPM2_SHA386_ID: initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL);break;
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
		displayDigest(temp->TEMPLATE_HASH,SHA256_DIGEST_LENGTH);
		displayDigest(temp->HASH,temp->HASH_LEN-8);
	//	printf("%s\n\n",temp->TEMPLATE_FILENAME);
	}
}

void freeIMAEntry(IMA_ENTRY* entry){
	//free(entry->HASH);
	free(entry->TEMPLATE_HASH);
	free(entry->TEMPLATE_DATA);
	free(entry->TEMPLATE_NAME);
	//free(entry->TEMPLATE_FILENAME);
}

const char* IMA_TEMPLATE_SHA256 = "sha256:\0";
const char* IMA_TEMPLATE_SHA1 = "sha1:\0";
const char* IMA_TEMPLATE_SHA384 = "sha384:\0";
const char* IMA_TEMPLATE_SHA512 = "sha512:\0";



uint16_t getHashAlgoFromTemplate(IMA_ENTRY* entry) {
	if(entry == NULL) {
		return 0;
	}
	//printf(" %d   ", memcmp(entry->TEMPLATE_DATA,IMA_TEMPLATE_SHA256,8));
	uint8_t isSha1 = memcmp(entry->TEMPLATE_DATA,IMA_TEMPLATE_SHA1,6);
	uint8_t isSha256 = memcmp(entry->TEMPLATE_DATA,IMA_TEMPLATE_SHA256,8);
	uint8_t isSha384 = memcmp(entry->TEMPLATE_DATA,IMA_TEMPLATE_SHA384,8);
	uint8_t isSha512 = memcmp(entry->TEMPLATE_DATA,IMA_TEMPLATE_SHA512,8);
	if(isSha1 == 0) return TPM2_SHA1_ID;
	else if(isSha256 == 0) return TPM2_SHA256_ID;
	else if(isSha384 == 0) return TPM2_SHA386_ID; // FIX TYPO IN NAMING
	else if(isSha512 == 0) return TPM2_SHA512_ID;
	return 0;
}

// Basically just returns an offset on the Template-Data for the Hash
uint8_t* getHashFromTemplateData(IMA_ENTRY* imaEntry) {
	uint8_t * hashPointer = NULL; // Will point to the hash part of the TEMPLATE_DATA 
	for (uint32_t i = 0; i < imaEntry->TEMPLATE_DATA_LEN; i++) {
		if( imaEntry->TEMPLATE_DATA[i] == '\0' && (i+1) < imaEntry->TEMPLATE_DATA_LEN ){
				hashPointer = &imaEntry->TEMPLATE_DATA[i+1];
				return hashPointer;
		}
	}
	return hashPointer;
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

// returns a uint32 with each bit set representing an enabled bank
uint32_t getEnabledBanks() {
	return 0;
}

TPMVERSION determineTPMVersion() {
	// find out how to check for tpm version TODO
	return TPMVERSION2;
}
