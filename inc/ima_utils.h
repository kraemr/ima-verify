

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
    EVP_MD_CTX* initEVPContext(uint16_t algoId);
    
    void freeIMAEntries(IMA_ENTRY* imaEntries,int n);
    void printAllIMAEntries(IMA_ENTRY* imaEntries,int n);
    
    uint32_t castByteBufUint32(uint8_t* buf);
    int32_t compute_hash(uint8_t* input,uint32_t len, uint8_t output[EVP_MAX_MD_SIZE], uint32_t *output_length,uint16_t algoId);
    
    uint64_t getFileSize(FILE * fp);
    uint32_t getEnabledBanks();

    uint16_t getHashAlgoFromTemplate(IMA_ENTRY* entry);
    uint8_t* getHashFromTemplateData(IMA_ENTRY* imaEntry);

#endif
