

#include "test.h"
#include <stdint.h>

int32_t parseIMALogCountTest(char* path,uint16_t hashType, uint32_t expectedCount ) {
    uint32_t count = parseIMALogCount(path, hashType);
    return count == expectedCount;
}

// Just checks the last one for now
int32_t parseIMALogTest(char *path, uint16_t hashType, IMA_ENTRY entryExpected){
    uint32_t count = parseIMALogCount(path, hashType);
    IMA_ENTRY* entryList = (IMA_ENTRY*)malloc((count) * sizeof(struct IMA_ENTRY));
    parseIMALog(path, hashType, entryList);
    // TODO check for a value // maybe check that the last ENtry is correct
    free(entryList);
}

int32_t compareQuotesTest(uint8_t* q1, uint16_t digest1Len,uint8_t* q2,uint16_t digest2Len) {
    return compareQuotes(q1,digest1Len,q2,digest2Len);    
}

int32_t verifyNewQuoteTest() {
    return 0;
}