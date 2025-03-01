#include "../inc/ima_tpm_types.h"
#include "../inc/ima_utils.h"
#include <openssl/sha.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h>
#define MAX_IMA_EVENT_REPLAY 1024 // For later to limit memory usage

void compute_sha256(uint8_t* input,uint32_t len, uint8_t output[EVP_MAX_MD_SIZE], uint32_t *output_length) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Error initializing EVP_MD_CTX\n");
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        printf("Digest initialization failed\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestUpdate(mdctx, input, len) != 1) {
        printf("Digest update failed\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestFinal_ex(mdctx, output, output_length) != 1) {
        printf("Digest finalization failed\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);
}



uint64_t getFileSize(FILE * fp){
	fseek(fp,0,SEEK_END);
	uint64_t t = ftell(fp);
	fseek(fp,0,SEEK_SET);
	return t;
}

static uint32_t parseIMALogCount(char* path,uint16_t hashType){
	uint8_t buffer[16384] = {0};
	FILE* fp = fopen(path,"rb");
	if(fp == NULL){
		printf("File Not Found or Missing Privileges\n");
		return 0;
	}
	int ima_i=0; 
	IMA_ENTRY* temp = malloc(sizeof(IMA_ENTRY));
 	// the binary data of an IMA_LOG Entry should fit
	// TODO: add check if end is reached, if not read the rest
	uint16_t hashLen = getTpmHashLength(hashType);
	printf("sanity check hashLen parseIMALogCount: %u\n",hashLen);
	uint64_t size = getFileSize(fp);
	
	int n = 1;
	uint32_t bytesToBeRead=1024;
	while(n) {
		size_t currentPos = ftell(fp);
		if(size - currentPos < 1024){
			bytesToBeRead = size - currentPos;
	//		printf("near End, new bytes per Read:%lu %lu %u\n",size,currentPos,bytesToBeRead);
		}
		n = fread(buffer,bytesToBeRead,1,fp);
		currentPos = ftell(fp);
	//	printf("%d\n",n);
		//NODE* node = malloc(sizeof(NODE));
		temp->TEMPLATE_DATA_LEN = 0;
		size_t offset = 0;
	//	printf("offset: %u\n",offset);
		temp->PCR_INDEX = castByteBufUint32(&buffer[offset]);
		offset += 4;
		offset += hashLen;
	//	printf("%x %x %x %x\n",buffer[offset],buffer[offset+1],buffer[offset+2],buffer[offset+3]);
		
		temp->TEMPLATE_NAME_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);

		offset += 4;
		offset += temp->TEMPLATE_NAME_LEN;		
		offset += 4;
		//printf("offset: %u\n",offset);
		temp->HASH_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4; 
		//printf("offset: %u\n",offset);

		offset += temp->HASH_LEN;
		temp->TEMPLATE_FILENAME_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		temp->TEMPLATE_FILENAME = (char*)malloc(temp->TEMPLATE_FILENAME_LEN * sizeof(char) );
		//printf("offset: %u\n",offset);
		memcpy(temp->TEMPLATE_FILENAME,&buffer[offset],temp->TEMPLATE_FILENAME_LEN);
		offset += temp->TEMPLATE_FILENAME_LEN;
		//offset += 4;
		//printf("Lengths pcr: %u tdl: %u tnl: %u tfl: %u hl: %u\n",temp->PCR_INDEX,temp->TEMPLATE_DATA_LEN,temp->TEMPLATE_NAME_LEN,temp->TEMPLATE_FILENAME_LEN,temp->HASH_LEN);
		fseek(fp,currentPos - bytesToBeRead + offset,SEEK_SET);
	//	printf("offset: %u\n",offset);
		currentPos = ftell(fp);
	//	printf("%llu %s \n",currentPos,temp->TEMPLATE_FILENAME);
		free(temp->TEMPLATE_FILENAME);
		ima_i++;
		
	}
	free(temp);
	fclose(fp);
	return ima_i;
}

// assumes NUL Terminated char*
// Normally path to IMALOG is /sys/kernel/security/ima/ascii_runtime_measurements or binary
// Format for IMA is 
// 4 byte PCR index
// Template Data Hash 20 bytes SHA-1
// 4 byte Template Name Length
// Template Name of n bytes NOT NUL TERMINATED
// 4 byte Template Data Length
// Template Name indicates FIELDS, for ima-sig for example: d-ng,n-ng,sig 
// 1024 ^ 32
static uint32_t parseIMALog(char* path,uint16_t hashType, IMA_ENTRY* imaEntryList){
	uint8_t buffer[16384] = {0};
	FILE* fp = fopen(path,"rb");
	if(fp == NULL){
		printf("File Not Found or Missing Privileges\n");
		return 0;
	}
	IMA_ENTRY* temp = NULL;
	int ima_i=0; 
 	// the binary data of an IMA_LOG Entry should fit
	// TODO: add check if end is reached, if not read the rest
	uint16_t hashLen = getTpmHashLength(hashType);
	uint64_t size = getFileSize(fp);
	int n = 1;
	uint32_t bytesToBeRead=1024;

	while(n) {
		size_t currentPos = ftell(fp);
		if(size - currentPos < 1024){
			bytesToBeRead = size - currentPos;
		}
		temp = &imaEntryList[ima_i];
		if(temp == NULL){ // this should NEVER Be null
			abort();
		}
		n = fread(buffer,bytesToBeRead,1,fp);
		currentPos = ftell(fp);
		size_t offset = 0;
		temp->PCR_INDEX = castByteBufUint32(&buffer[offset]);
		offset += 4;

		temp->PCR_VALUE = (uint8_t*)malloc(hashLen * sizeof(uint8_t));
		memcpy(temp->PCR_VALUE,&buffer[offset],hashLen);
		offset += hashLen;
		
		temp->TEMPLATE_NAME_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		
		temp->TEMPLATE_NAME = (char*)malloc(temp->TEMPLATE_NAME_LEN * sizeof(char) );
		memcpy(temp->TEMPLATE_NAME,&buffer[offset],temp->TEMPLATE_NAME_LEN);		
		offset += temp->TEMPLATE_NAME_LEN;
		
		temp->TEMPLATE_DATA_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		temp->HASH_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		
		temp->HASH = (uint8_t*)malloc(temp->HASH_LEN * sizeof(uint8_t) );
		memcpy(temp->HASH,&buffer[offset+8],temp->HASH_LEN-8);
		offset += temp->HASH_LEN;

		printf("%d: ",ima_i);
		displayDigest(temp->HASH, SHA256_DIGEST_LENGTH);
		temp->TEMPLATE_FILENAME_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		temp->TEMPLATE_FILENAME = (char*)malloc(temp->TEMPLATE_FILENAME_LEN * sizeof(char) );
		memcpy(temp->TEMPLATE_FILENAME,&buffer[offset],temp->TEMPLATE_FILENAME_LEN);
		offset += temp->TEMPLATE_FILENAME_LEN;
	/*	if(buffer[offset] != 0 && buffer[offset+1] != 0 && buffer[offset+2] != 0 && buffer[offset+3] != 0 ){
		//	printf("Padding missing???\n");
		}*/
		//offset  += 4; // 4 byte zero padding
		fseek(fp,currentPos - bytesToBeRead + offset,SEEK_SET);
		currentPos = ftell(fp);
		ima_i++;
	}
	fclose(fp);
	return ima_i;
}

// this function assumes that out is allocated already
void tpmEmulatedExtend(uint8_t* hash1,uint8_t* hash2,uint16_t hashType,uint8_t* out) {
	uint16_t hashLen = getTpmHashLength(hashType);
	uint32_t outputLen = 0;
	uint8_t extended[SHA256_DIGEST_LENGTH*2];	
	memcpy(extended,hash1,hashLen);
	memcpy(&extended[hashLen],hash2,hashLen);
	printf("HASH1: ");
	displayDigest(hash1,SHA256_DIGEST_LENGTH);
	printf("HASH2: ");
	displayDigest(hash2,SHA256_DIGEST_LENGTH);
	printf("HASH CONCAT: ");
	displayDigest(extended,SHA256_DIGEST_LENGTH*2);
	//exit(1);
	compute_sha256(extended,SHA256_DIGEST_LENGTH*2,out,&outputLen);
	displayDigest(out,outputLen);
}




// SHOULD BE DONE ITERATIVELY TO AVOID PERFORMANCE DEGRADATION
// JUST FOR TESTING !!!!!!
// at some point DIGEST_TO_MATCH and currentHash should be Equal if NOT then no valid
void replayIMALog(IMA_ENTRY* imaEntries,uint32_t n,uint8_t* DIGEST_TO_MATCH){
	uint8_t* currentHash = malloc(EVP_MAX_MD_SIZE);
	uint8_t* result = malloc(EVP_MAX_MD_SIZE);
	
	memcpy(currentHash,imaEntries[0].HASH,32);
	memcpy(result,imaEntries[0].HASH,32);
	printf("boot_aggregate: ");
	displayDigest(currentHash,32);
	uint32_t currentPos = 0;

	for( uint32_t i = 1; i < n; i++ ) {
		memcpy(currentHash,result,32);
		tpmEmulatedExtend(currentHash, imaEntries[i].HASH,TPM2_SHA256_ID,result);
		printf("%d %s:  ",i,imaEntries[i].TEMPLATE_FILENAME);
		displayDigest(result,32);

		if( memcmp() ){

		}
		

		//uint32_t t;
		//compute_sha256(currentHash,32,result,&t);
		//displayDigest(result,32);
	}
}

/**
There is actually a file with measurements count, which can be used*/

// We dont now the number of entries beforehand
// One approach: Read entire File and check for Entry count
// Perhaps just use a linekd list?
int main(int argc,char* argv[]) {
	char* path = argv[1];
	char* quote_path = argv[2]; // Read in quote at path
	uint32_t count = parseIMALogCount(path,TPM2_SHA256_ID);
	printf("IMA ENTRIES COUNT: %u\n",count);
	IMA_ENTRY* imaEntries = (IMA_ENTRY*)malloc(count * sizeof(struct IMA_ENTRY));
	uint32_t len = parseIMALog(path,TPM2_SHA256_ID,imaEntries);
	replayIMALog(imaEntries,count,NULL);
	freeIMAEntries(imaEntries,len);
	free(imaEntries);	
}
