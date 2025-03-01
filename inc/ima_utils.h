

#ifndef IMA_UTILS_H
    #define IMA_UTILS_H
    #include "ima_tpm_types.h"
    #include <stdint.h>
    #include <stdio.h>
    uint32_t getMeasurementCount();
    uint32_t getViolationsCount();
    void displayDigest(uint8_t *pcr, int32_t n);
    void displayN(uint8_t *pcr, int32_t n);
    uint32_t getTpmHashLength(uint16_t algoId);
    void freeIMAEntries(IMA_ENTRY* imaEntries,int n);
    void printAllIMAEntries(IMA_ENTRY* imaEntries,int n);
    EVP_MD_CTX* initEVPContext(HASHTYPE hashType);
    uint32_t castByteBufUint32(uint8_t* buf);

#endif
