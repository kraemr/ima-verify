/*
* Copyright (c) International Business Machines  Corp., 2009
*
* Authors:
* Mimi Zohar <zohar@us.ibm.com>
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License as
* published by the Free Software Foundation, version 2 of the
* License.
*
* File: ima_boot_aggregate.c
*
* Calculate a SHA1 boot aggregate value based on the TPM
* binary_bios_measurements.
*
* Requires openssl; compile with -lcrypto option
*/
#include "ima_tpm_types.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>

//char *TCID = "ima_boot_aggregate";
int32_t TST_TOTAL = 1;
static void displayDigest(uint8_t *pcr, int32_t n)
{
	int32_t i;
	for (i = 0; i < n; i++)
		printf("%x", pcr[i] );
	printf("\n");
}

static void displayN(uint8_t *pcr, int32_t n)
{
	int32_t i;
	for (i = 0; i < n; i++)
		printf("%c ", pcr[i] );
	printf("\n");
}


TPMVERSION determineTPMVersion() {
	// find out how to check for tpm version TODO
	return TPMVERSION2;
}

uint32_t getHashLength(uint16_t algoId) {
	switch (algoId) {
		case TPM2_SHA1_ID: return SHA_DIGEST_LENGTH;break;
		case TPM2_SHA256_ID: return SHA256_DIGEST_LENGTH;break;
		case TPM2_SHA386_ID: return SHA384_DIGEST_LENGTH;break;
		case TPM2_SHA512_ID: return SHA512_DIGEST_LENGTH;break;
		case TPM2_SM3_256: return 0;break; // ?????? 
	}
	return 0;
}

EVP_MD_CTX* initEVPContext(HASHTYPE hashType){
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if(mdctx == NULL) {
		return NULL;
	}
	int32_t initializationResult = 0;
	switch (hashType){
		case TPM_SHA1:  initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL); break;
		case TPM_SHA256: initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL); break;
		case TPM_SHA512: initializationResult = EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL); break;
	}
	return mdctx;
}


static int32_t checkSpecId(FILE * fp,SPEC_ID_EVENT* spec) {
	uint32_t t=0;
	fread(&t,4,1,fp);
	t = 0;
	fread(&t,4,1,fp);
	printf("Found Spec ID event\n");
	fseek(fp,20,SEEK_CUR);
	t = 0;
	fread(&t,4,1,fp);
	uint8_t eventData[16384]={0};
	printf("event Size: %d\n",t);
	fread(eventData,t,1,fp);
	displayDigest(eventData,t);	
	//printf("%s\n",eventData);
	return 1;
}

static void readTpm2BiosLog(FILE * fp,TCG_PCR_EVENT2** eventListRef,uint32_t* eventCount) {
	SPEC_ID_EVENT event;
	
	fseek(fp,0,SEEK_END);
	uint32_t be = ftell(fp);
	fseek(fp,0,SEEK_SET);
	
	int32_t ret = checkSpecId(fp,&event);
	uint32_t evListSize = sizeof(TCG_PCR_EVENT2) * 100;
	(*eventListRef) = malloc(evListSize); 
	TCG_PCR_EVENT2* eventList = (*eventListRef);
	while(!feof(fp)){
		if((*eventCount) >= evListSize){
			evListSize = evListSize*2;
			eventList = realloc(eventList,evListSize);
			printf("needed to realloc %u bytes",evListSize);
		}
		TCG_PCR_EVENT2* e = &eventList[(*eventCount)];
		fread(&e->pcrIndex,4,1,fp);
		fread(&e->eventType,4,1,fp);
		fread(&e->digests.count,4,1,fp);
		if(feof(fp)){
			break;		
		}
		e->digests.digestList = (TCG_PCR_EVENT_DIGEST2* )malloc( sizeof(TCG_PCR_EVENT_DIGEST2) * (e->digests.count) );
		
		for(int i = 0; i < e->digests.count;i++){
			fread(&e->digests.digestList[i].algorithmId,2,1,fp);
			uint32_t len = getHashLength(e->digests.digestList[i].algorithmId);
			fread(e->digests.digestList[i].digest,len,1,fp);
		}

		fread(&e->eventSize,4,1,fp);
		e->eventData = malloc(e->eventSize);
		fread(e->eventData,e->eventSize,1,fp);	
		#ifdef DEBUG
			printf("pcr: %d \neventType: %d\ncount: %d\n",e->pcrIndex,e->eventType,e->digests.count);
			printf("eventSize: %d\n",e->eventSize);
			displayN(e->eventData,e->eventSize); // useful if no NUL at end of "string" which is often the case sadly
			printf("eventCount %d\n",(*eventCount));
		#endif
		(*eventCount)++;
	}
}

void printAllEvents(TCG_PCR_EVENT2* eventList,uint32_t eventCount) {
	for(int i= 0; i < eventCount;i++){
		TCG_PCR_EVENT2* e = &eventList[i];
		printf("%u %u %u\n",e->pcrIndex,e->eventType,e->eventSize);
	}
}

void freeEventLog(TCG_PCR_EVENT2* eventList, uint32_t eventCount) {
	for( uint32_t i = 0; i < eventCount; i++ ) {
		free( eventList[i].eventData );
		free( eventList[i].digests.digestList );
	}
	free(eventList);
}


static void verifyBootAggregate(const char * str) {
	uint8_t bootAggregate[EVP_MAX_MD_SIZE];
	uint8_t digests[NUM_PCRS][EVP_MAX_MD_SIZE];
	TCG_PCR_EVENT2* eventList=NULL;
	uint32_t eventCount=0;
	FILE * fp = fopen(str,"rb");
	uint32_t i = 0;
	for (;i < NUM_PCRS; i++) memset(digests[i], 0, EVP_MAX_MD_SIZE);
	i = 0;
	uint32_t outLen = 0;
	
	readTpm2BiosLog(fp,&eventList,&eventCount);
	if(eventList == NULL){
		printf("EventList was NUll \n");
	}
	printf("read success\n");

	for(i=0;i < eventCount; i++ ) {
		TCG_PCR_EVENT2* eref = &eventList[i];
		EVP_MD_CTX* mdctx = initEVPContext(TPM_SHA256);		
		#ifdef DEBUG 
			printf("i: %d current Pcr [%d]:",i,eref->pcrIndex);
			displayDigest(digests[eref->pcrIndex],SHA256_DIGEST_LENGTH);
		#endif
		EVP_DigestUpdate(mdctx,digests[eref->pcrIndex] ,SHA256_DIGEST_LENGTH);
		EVP_DigestUpdate(mdctx,eref->digests.digestList->digest,SHA256_DIGEST_LENGTH);
		EVP_DigestFinal_ex(mdctx, digests[eref->pcrIndex], &outLen);
		EVP_MD_CTX_free(mdctx); // probably can be optimised away 
	}
	
	memset(&bootAggregate, 0, SHA256_DIGEST_LENGTH);
	EVP_MD_CTX* mdctx = initEVPContext(TPM_SHA256);	
	
	#ifdef DEBUG
		printf("\n Final State of virtual Pcrs: \n");
	#endif

	for (i = 0; i < NUM_PCRS; i++) {
		#ifdef DEBUG
			printf("current Pcr [%d]:",i);
			displayDigest(digests[i],SHA256_DIGEST_LENGTH);
		#endif
		EVP_DigestUpdate(mdctx,digests[i], SHA256_DIGEST_LENGTH);
	}
	
	EVP_DigestFinal_ex(mdctx,bootAggregate,&outLen);
	EVP_MD_CTX_free(mdctx); // probably can be optimised away 
	printf("boot_aggregate:");
	displayDigest(bootAggregate,outLen);
	fclose(fp);
	freeEventLog(eventList,eventCount);
	return;
/*
	while( fread(&event, sizeof(event.header), 1, fp) ){		
		#ifdef DEBUG 
			printf("%03u ", event.header.pcr);
			displayDigest(event.header.digest,SHA256_DIGEST_LENGTH);
		#endif
		EVP_MD_CTX* mdctx = initEVPContext(TPM_SHA256);
		
		EVP_DigestUpdate(mdctx,pcr[event.header.pcr].digest,SHA256_DIGEST_LENGTH);
		EVP_DigestUpdate(mdctx,event.header.digest,SHA256_DIGEST_LENGTH);
		EVP_DigestFinal_ex(mdctx, pcr[event.header.pcr].digest, &outLen);

		fread(event.data, event.header.len, 1, fp); // apparently isnt needed
		EVP_MD_CTX_free(mdctx); // probably can be optimised away 
	}
	
	fclose(fp);
	memset(&bootAggregate, 0, SHA256_DIGEST_LENGTH);
	EVP_MD_CTX* mdctx = initEVPContext(TPM_SHA256);	
	for (i = 0; i < NUM_PCRS; i++) {
		EVP_DigestUpdate(mdctx, pcr[i].digest, SHA256_DIGEST_LENGTH);
	}

	EVP_DigestFinal_ex(mdctx,bootAggregate,&outLen);
	EVP_MD_CTX_free(mdctx); // probably can be optimised away 
	printf("boot_aggregate:");
	displayDigest(bootAggregate,outLen);
*/
}


int main(int argc, char *argv[])
{
	if(argc < 2){
		printf("Missing Args");
		return 1;
	}

	verifyBootAggregate(argv[1]);
	return 0;
}