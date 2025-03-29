#include "../inc/ima_tpm_types.h"
#include "../inc/ima_verify.h"
#include "../inc/ima_utils.h"
#include "../inc/config.h"
#include <stdint.h>

// TESTCASES
extern int32_t parseIMALogCountTest(char* path,uint16_t hashType, uint32_t expectedCount );
extern int32_t parseIMALogTest(char *path, uint16_t hashType, IMA_ENTRY entryExpected);
extern int32_t compareQuotesTest(uint8_t* q1, uint16_t digest1Len,uint8_t* q2,uint16_t digest2Len);
// TESTCASES

char * SHA256_IMA_LOG_FILENAME  = "binary_runtime_measurements_sha256";
char * SHA1_IMA_LOG_FILENAME  = "binary_runtime_measurements_sha1";

int32_t runTests(){
    int32_t res = 0;
    int32_t hasNoErrors = 1;
    res = parseIMALogCountTest(SHA256_IMA_LOG_FILENAME,TPM2_SHA256_ID,3591);
    if(!res) hasNoErrors = 0;

    return hasNoErrors;
}

int main() {
    int32_t results = runTests();
    if(results == 0){
        printf("There were no errors\n");
    }
    else{
        printf("One or more Tests had errors see test ouput for more info\n");
    }
}