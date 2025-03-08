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

#pragma region IMA_LOGP_ARSING
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

		temp->TEMPLATE_HASH = (uint8_t*)malloc(hashLen * sizeof(uint8_t));
		memcpy(temp->TEMPLATE_HASH,&buffer[offset],hashLen);
		offset += hashLen;
		
		temp->TEMPLATE_NAME_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		
		temp->TEMPLATE_NAME = (char*)malloc(temp->TEMPLATE_NAME_LEN * sizeof(char) );
		memcpy(temp->TEMPLATE_NAME,&buffer[offset],temp->TEMPLATE_NAME_LEN);		
		offset += temp->TEMPLATE_NAME_LEN;
		displayN((uint8_t*)temp->TEMPLATE_NAME,temp->TEMPLATE_NAME_LEN);
		
		temp->TEMPLATE_DATA_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;

		temp->TEMPLATE_DATA = (uint8_t*)malloc(temp->TEMPLATE_DATA_LEN);
		memcpy(temp->TEMPLATE_DATA,&buffer[offset+4],temp->TEMPLATE_DATA_LEN); // TODO: make it non static and parse the algoname
		offset += temp->TEMPLATE_DATA_LEN;

		temp->HASH_ALGO = getHashAlgoFromTemplate(temp);
		temp->HASH = getHashFromTemplateData(temp);

		printf("id: %d Algo: %d %d ",ima_i,temp->HASH_ALGO,getTpmHashLength(temp->HASH_ALGO));
		displayDigest(temp->HASH,getTpmHashLength(temp->HASH_ALGO));



		
		printf("%d: ",ima_i);
		displayDigest(temp->HASH, SHA256_DIGEST_LENGTH);
		
	//	temp->TEMPLATE_FILENAME_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
	//	offset += 4;
	//	temp->TEMPLATE_FILENAME = (char*)malloc(temp->TEMPLATE_FILENAME_LEN * sizeof(char) );
	//	memcpy(temp->TEMPLATE_FILENAME,&buffer[offset],temp->TEMPLATE_FILENAME_LEN);
	//	offset += temp->TEMPLATE_FILENAME_LEN;
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
void tpmEmulatedExtend(uint8_t* hash1,uint8_t* hash2,uint16_t hashAlgoId,uint8_t* out) {
	uint16_t hashLen = getTpmHashLength(hashAlgoId);
	uint32_t outputLen = 0;
	uint8_t extended[SHA256_DIGEST_LENGTH*2];	
	memcpy(extended,hash1,hashLen);
	memcpy(&extended[hashLen],hash2,hashLen);
	printf("HASH1: ");
	displayDigest(hash1,hashLen);
	printf("HASH2: ");
	displayDigest(hash2,hashLen);
	printf("HASH CONCAT: ");
	displayDigest(extended,hashLen*2);
	compute_hash(extended,hashLen*2,out,&outputLen,hashAlgoId);
	displayDigest(out,outputLen);
}


/* 
	There is actually a file with measurements count, which can be used 
*/
static void test(IMA_ENTRY* imaEntries, int32_t count) {
	uint8_t zeroes[EVP_MAX_MD_SIZE] = {0};
	uint32_t output_length = 0;
	uint8_t out[EVP_MAX_MD_SIZE];
	uint8_t pcrs[24][EVP_MAX_MD_SIZE];
	uint16_t hashAlgo = getHashAlgoFromTemplate(&imaEntries[0]); 
	uint32_t hashLen = getTpmHashLength(hashAlgo);
	memcpy(pcrs[imaEntries->PCR_INDEX],zeroes,hashLen);
	
	for(uint32_t i=0;i < count -1; i++ ) {
		IMA_ENTRY* eref = &imaEntries[i];
		EVP_MD_CTX* mdctx = initEVPContext(hashAlgo);		
		#ifdef DEBUG 
			printf("i: %d current Pcr [%d]:",i,eref->pcrIndex);
			displayDigest(digests[eref->pcrIndex],SHA256_DIGEST_LENGTH);
		#endif
		printf("old: ");
		displayDigest(pcrs[eref->PCR_INDEX], hashLen);
		
		EVP_DigestUpdate(mdctx,pcrs[eref->PCR_INDEX] ,hashLen);
		
		//printf("new: ");
		displayDigest(eref->HASH, hashLen);
		
		EVP_DigestUpdate(mdctx,eref->HASH,hashLen);
		EVP_DigestFinal_ex(mdctx, pcrs[eref->PCR_INDEX], &output_length);
		 
		printf("digest: ");
		displayDigest(pcrs[eref->PCR_INDEX], hashLen);
		printf("\n\n");
		
		EVP_MD_CTX_free(mdctx); // probably can be optimised away 
	}
}

// We dont now the number of entries beforehand
// One approach: Read entire File and check for Entry count
// Perhaps just use a linekd list?
int main(int argc,char* argv[]) {
	char* path = argv[1];
	const char* quote_path = argv[2]; // Read in quote at path
	const char* hashFlag = argv[3];
	int32_t hashFlagLen = strlen(hashFlag); 
	uint16_t hashType = 0;

	if(hashFlagLen >= 4 && memcmp(hashFlag,"sha1",4) == 0){
		hashType = TPM2_SHA1_ID;
	}
	else if(hashFlagLen >= 6 && memcmp(hashFlag,"sha256",6) == 0){
		hashType = TPM2_SHA256_ID;
	}

	if(hashType == 0) {
		printf("Format of Template Hash Missing! possible values: sha1,sha256\n");
		exit(0);
	}
	uint32_t count = parseIMALogCount(path,hashType);
	printf("IMA ENTRIES COUNT: %u\n",count);
	IMA_ENTRY* imaEntries = (IMA_ENTRY*)malloc(count * sizeof(struct IMA_ENTRY));
	uint32_t len = parseIMALog(path,hashType,imaEntries);
	test(imaEntries,count);
	freeIMAEntries(imaEntries,len);
	free(imaEntries);	
}
