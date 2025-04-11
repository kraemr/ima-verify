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

#pragma region IMA_LOG_PARSING
uint32_t parseIMALogCount(char* path,uint16_t hashType){
	uint8_t buffer[16384] = {0};
	FILE* fp = fopen(path,"rb");
	if(fp == NULL){
		printf("File Not Found or Missing Privileges\n");
		return 0;
	}

	uint32_t ima_i=1; 
	IMA_ENTRY* temp = (IMA_ENTRY*)malloc(sizeof(IMA_ENTRY));
	uint16_t hashLen = (uint32_t)getTpmHashLength(hashType);
	uint64_t size = (uint64_t)getFileSize(fp);	
	int32_t n = 1;
	uint32_t bytesToBeRead= 1024;

	while(n) {
		size_t currentPos = ftell(fp);
		if(size - currentPos < 1024){
			bytesToBeRead = size - currentPos;
		}
		n = fread(buffer,bytesToBeRead,1,fp);
		currentPos = ftell(fp);

		temp->TEMPLATE_DATA_LEN = 0;
		size_t offset = 0;
		temp->PCR_INDEX = castByteBufUint32(&buffer[offset]);
		offset += 4;
		offset += hashLen;
		temp->TEMPLATE_NAME_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		offset += temp->TEMPLATE_NAME_LEN;
		temp->TEMPLATE_DATA_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		offset += temp->TEMPLATE_DATA_LEN;
		
		fseek(fp,currentPos - bytesToBeRead + offset,SEEK_SET);
		currentPos = ftell(fp);

		if(currentPos == size){
			return ima_i;
		}

		ima_i++;
	}

	free(temp);
	fclose(fp);
	return ima_i;
}

#define BUFFERSIZE 16384
// parseIMALogSeqeuential
// resumes at a given event index, and loads everything after that into imaEntryList
uint32_t parseIMALogSeq(FILE * fp,uint16_t hashType, IMA_ENTRY* imaEntryList) {
	uint8_t buffer[BUFFERSIZE] = {0};
	IMA_ENTRY* temp = NULL;
	int ima_i=0; 	
	uint64_t size = getFileSize(fp);
	if(feof(fp)) return 0; // we are at the end already, meaning no new data
	uint16_t hashLen = getTpmHashLength(hashType);
	uint32_t bytesToBeRead=BUFFERSIZE;
	int n = 0;

	while(feof(fp) == 0) {
		size_t currentPos = ftell(fp);
		if(size - currentPos < BUFFERSIZE){
			bytesToBeRead = size - currentPos;
		}
		temp = &imaEntryList[ima_i];
		if(temp == NULL){ // this should NEVER Be null
			abort();
		}
		n = fread(buffer,bytesToBeRead,1,fp);
		currentPos = ftell(fp);

		temp->EVENT_INDEX = ima_i;

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

		temp->TEMPLATE_DATA_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		temp->TEMPLATE_DATA = (uint8_t*)malloc(temp->TEMPLATE_DATA_LEN);
		memcpy(temp->TEMPLATE_DATA,&buffer[offset+4],temp->TEMPLATE_DATA_LEN); // TODO: make it non static and parse the algoname
		offset += temp->TEMPLATE_DATA_LEN;

		temp->HASH_ALGO = getHashAlgoFromTemplate(temp);
		temp->HASH = getHashFromTemplateData(temp);
	
		fseek(fp,currentPos - bytesToBeRead + offset,SEEK_SET);
		currentPos = ftell(fp);
		if(currentPos == size){
			return ima_i;
		}
		ima_i++;
	}
	return ima_i;
}

uint32_t parseIMALog(char* path,uint16_t hashType, IMA_ENTRY* imaEntryList){
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

		temp->EVENT_INDEX = ima_i;

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

		temp->TEMPLATE_DATA_LEN = castByteBufUint32((uint8_t*)&buffer[offset]);
		offset += 4;
		temp->TEMPLATE_DATA = (uint8_t*)malloc(temp->TEMPLATE_DATA_LEN);
		memcpy(temp->TEMPLATE_DATA,&buffer[offset+4],temp->TEMPLATE_DATA_LEN); // TODO: make it non static and parse the algoname
		offset += temp->TEMPLATE_DATA_LEN;

		temp->HASH_ALGO = getHashAlgoFromTemplate(temp);
		temp->HASH = getHashFromTemplateData(temp);
	
		fseek(fp,currentPos - bytesToBeRead + offset,SEEK_SET);
		currentPos = ftell(fp);
		if(currentPos == size){
			return ima_i;
		}
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
	displayDigest(hash1,hashLen);
	displayDigest(hash2,hashLen);
	displayDigest(extended,hashLen*2);
	compute_hash(extended,hashLen*2,out,&outputLen,hashAlgoId);
	displayDigest(out,outputLen);
}

void rebuildIMACache(IMA_ENTRY* imaEntries, int32_t count, uint8_t pcrs[30][EVP_MAX_MD_SIZE] ) {
	uint8_t zeroes[EVP_MAX_MD_SIZE] = {0};
	uint32_t output_length = 0;
	uint8_t out[EVP_MAX_MD_SIZE];
	uint16_t hashAlgo = getHashAlgoFromTemplate(&imaEntries[0]); 
	uint32_t hashLen = getTpmHashLength(hashAlgo);
	memcpy(pcrs[imaEntries->PCR_INDEX],zeroes,hashLen);
	for(uint32_t i=0;i < count; i++ ) {
		IMA_ENTRY* eref = &imaEntries[i];
		EVP_MD_CTX* mdctx = initEVPContext(hashAlgo);		
		EVP_DigestUpdate(mdctx,pcrs[eref->PCR_INDEX] ,hashLen);
		EVP_DigestUpdate(mdctx,eref->TEMPLATE_HASH,hashLen);
		EVP_DigestFinal_ex(mdctx, pcrs[eref->PCR_INDEX], &output_length);
		EVP_MD_CTX_free(mdctx); // probably can be optimised away 
	
		//displayDigest(pcrs[10],hashLen);

		//displayDigest(eref->TEMPLATE_HASH,hashLen);
	
	}
	//printf("PCR_AGGREGATE: ");
//	displayDigest(pcrs[10],hashLen);
}

/*
	For now just check that the quote digest matches the digest we generate
	Check signature aswell later

	returns 1 if quoteDigest matches pcr
	returns 0 if not

	Both need to be of same hash type
*/
int32_t attest(uint8_t* pcr,uint8_t* quoteDigest,uint32_t hashLen) {
	// a result of 0 indicates that all bytes match exactly
	if(memcmp(pcr,quoteDigest,hashLen)==0) {
		return 1;
	}
	else{
		return 0;
	}

}

uint8_t compareQuotes(uint8_t* q1, uint16_t digest1Len,uint8_t* q2,uint16_t digest2Len) {
	uint8_t anyQuoteNull = q1 == NULL  || q2 == NULL;
	uint8_t digestDiffSize = digest1Len != digest2Len;
	if(anyQuoteNull ||  digestDiffSize){
		return 0;
	}
	int32_t result = memcmp(q1, q2,digest1Len);
	return result == 0 ? 1 : 0;  // if memcmp returns 0 true else false
} 


uint8_t verifyNewQuote(
		uint8_t* quoteDigest, // quote to match
		IMA_ENTRY* newEntries, // 
		uint8_t pcrs[24][EVP_MAX_MD_SIZE],
		IMA_ENTRY** entriesCache, 
		uint32_t eventsCount,
		uint32_t newEntriesCount,
		uint32_t* size
){
	uint8_t zeroes[EVP_MAX_MD_SIZE] = {0};
	uint32_t output_length = 0;
	uint8_t out[EVP_MAX_MD_SIZE];
	uint16_t hashAlgo = getHashAlgoFromTemplate(newEntries); 
	uint32_t hashLen = getTpmHashLength(hashAlgo);

	if (eventsCount > (*size) ) {
	//	printf("Realloc\n");
		(*entriesCache) = (IMA_ENTRY*)realloc((*entriesCache),(eventsCount+1000) * sizeof(struct IMA_ENTRY));
		(*size) = eventsCount;
	}

	for(uint32_t i = 0; i < newEntriesCount; i++){
		IMA_ENTRY* entry = &newEntries[i];
		EVP_MD_CTX* mdctx = initEVPContext(hashAlgo);		
		EVP_DigestUpdate(mdctx,pcrs[entry->PCR_INDEX] ,hashLen);
		EVP_DigestUpdate(mdctx,entry->TEMPLATE_HASH,hashLen);
		EVP_DigestFinal_ex(mdctx, pcrs[entry->PCR_INDEX], &output_length);
		EVP_MD_CTX_free(mdctx); 
	}
		//printf("PCR_AGGREGATE: ");
		//displayDigest(pcrs[10],hashLen);
		return compareQuotes(quoteDigest,hashLen,pcrs[10],hashLen);
}


#ifdef IMA_VERIFY_STANDALONE

// We dont now the number of entries beforehand
// One approach: Read entire File and check for Entry count
// Perhaps just use a linekd list?
int main(int argc,char* argv[]) {
	char* path = argv[1];
	const char* quote_path = argv[2]; // Read in quote at path
	const char* hashFlag = argv[3];
	int32_t hashFlagLen = strlen(hashFlag); 
	uint16_t hashType = 0;
	uint8_t pcrs[30][EVP_MAX_MD_SIZE];
	uint32_t cacheElementCount = 0; // the current amount of elements inseide of the cache 
	uint32_t cacheSize = 0; // The Allocated size of the cache 

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
	
	IMA_ENTRY* imaEntries = (IMA_ENTRY*)malloc((count) * sizeof(struct IMA_ENTRY));
	//uint32_t len = parseIMALog(path,hashType,imaEntries);
	FILE * fp = fopen(path,"rb");
	int c = parseIMALogSeq(fp,hashType,imaEntries);
	fclose(fp);

	//printf("len %d count %d\n",len,count);
	//for(int i = 0; i < count; i++){
      //  displayDigest(imaEntries[i].TEMPLATE_HASH, SHA256_DIGEST_LENGTH);
    //}
	//cacheSize = count-4;
	//cacheElementCount= cacheSize;

//	memcpy(newEntries,&imaEntries[count],4 * sizeof(struct IMA_ENTRY) ); // simulate us adding 4 new entries
	
	rebuildIMACache(imaEntries,count,pcrs);
	printf("PCR \n");
	displayDigest(pcrs[10], SHA256_DIGEST_LENGTH);

//	printf("Cache Rebuilt\n");
//	printf("Incrementally add now %u %u\n",cacheElementCount,count);
	//cacheElementCount += 4;

	// simulate incrementally adding new Events to the pcrs and storing them in the cache 
//	verifyNewQuote(NULL,newEntries,pcrs,&imaEntries,cacheElementCount,4,&cacheSize);
	
	freeIMAEntries(imaEntries,count);
	free(imaEntries);	
//	free(newEntries);
}
#endif