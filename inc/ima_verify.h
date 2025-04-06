

#include <stdint.h>
#include "ima_tpm_types.h"
extern uint8_t verifyNewQuote(
		uint8_t* quoteDigest, // quote to match
		IMA_ENTRY* newEntries, // 
		uint8_t pcrs[24][EVP_MAX_MD_SIZE],
		IMA_ENTRY** entriesCache, 
		uint32_t eventsCount,
		uint32_t newEntriesCount,
		uint32_t* size
);
extern uint8_t compareQuotes(uint8_t* q1, uint16_t digest1Len,uint8_t* q2,uint16_t digest2Len);
extern uint32_t parseIMALogCount(char* path,uint16_t hashType);
extern uint32_t parseIMALog(char* path,uint16_t hashType, IMA_ENTRY* imaEntryList);
extern void rebuildIMACache(IMA_ENTRY* imaEntries, int32_t count, uint8_t pcrs[30][EVP_MAX_MD_SIZE] );
extern uint32_t parseIMALogSeq(FILE * fp,uint16_t hashType, IMA_ENTRY* imaEntryList);