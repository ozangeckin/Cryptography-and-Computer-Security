#include "crypto_aead.h"
#include "stdint.h"
#include "schwaemmconfig.h"
#include "util.h"
#include "string.h" 
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1


#ifdef _DEBUG
#include "stdio.h"
#endif

#ifdef _DEBUG
    void pstate(uint32_t *state){
        for(int i=0; i<WORD(STATESIZE); i++){
            printf("%02d:%08x ", i, state[i]);
            if(i%4==3) printf("\n");
        }
        printf("\n");
    }

    void countstate(uint32_t *state){
        for(int i=0; i<WORD(STATESIZE); i++)
            state[i]=i;
    }

    void p8state(uint32_t *state){
        u8 *s;
        s=(u8 *)(state);
        for(int i=0; i<BYTE(STATESIZE); i++){
            printf("%02x ", s[i]);
            if(i%4==3) printf(" ");
        }
        printf("\n");
    }
#endif

void initialize(uint32_t *state, const u8 *key, const u8 *nonce){
    for(int i=0; i<CRYPTO_NPUBWORDS; i++)
        state[i]=load32((u8 *)nonce+(4*i));
    for(int i=0; i<CRYPTO_KEYWORDS; i++)
        state[i+CRYPTO_NPUBWORDS]=load32((u8 *)(key)+(4*i));
    sparklePermutation(state, STEPSBIG);
}

void  processAD(uint32_t *state, const u8 *ad,  u64 adlen){
    if(adlen != 0){
        int constA = (adlen % BYTE(RATE) != 0) ? PADADCONST : NOPADADCONST;
        while (adlen > BYTE(RATE)){
            rho1(state, (uint32_t *)ad);
            RATEWHITENING(state);
            sparklePermutation(state, STEPSSLIM);
            ad += BYTE(RATE);
            adlen -= BYTE(RATE);
        }
        uint32_t lBlock[WORD(RATE)];
        pad(lBlock, (u8*)(ad), (u8)(adlen));

        rho1(state, lBlock);
        INJECTCONST(state, constA);
        RATEWHITENING(state);
        sparklePermutation(state, STEPSBIG);
    }
}

void  encryptPT(uint32_t *state, u8 *c, u64 *clen, const u8 *m, u64 mlen, const unsigned char *k){
    *clen = mlen + CRYPTO_ABYTES;
    if (mlen != 0){
        int constM = (mlen % BYTE(RATE) != 0) ? PADPTCONST : NOPADPTCONST;

        while (mlen > BYTE(RATE)){
            memcpy(c, m, BYTE(RATE));
            rho2((uint32_t *)(c), state);
            rho1(state, (uint32_t *)(m));
            RATEWHITENING(state);
            sparklePermutation(state, STEPSSLIM);
            m += BYTE(RATE);
            c += BYTE(RATE);
            mlen -= BYTE(RATE);
        }
        uint32_t lBlock[WORD(RATE)];
        pad(lBlock, (u8 *)(m), mlen);

        rho2(lBlock, state);
        memcpy(c, lBlock, mlen);
        pad(lBlock, (u8 *)(m), mlen);
        rho1(state, lBlock);
        INJECTCONST(state, constM);
        RATEWHITENING(state);
        sparklePermutation(state, STEPSBIG);
    }
        memcpy(c+mlen, (u8*)(state)+BYTE(RATE), CRYPTO_ABYTES);

        for(int i=0; i<CRYPTO_ABYTES; i++){
            (c+mlen)[i] ^= k[i];
        }
}

int verifyTag(uint32_t *state, u8 *tag){
    u8 *tag1;
    tag1=(u8*)(state);
    tag1 += BYTE(RATE);
    unsigned int r = 0;
    for (int i=0; i<CRYPTO_ABYTES; i++)
        r |= tag1[i] ^ tag[i];
    return (((r-1) >> 8) &1)-1;
}

int  decryptCT(uint32_t *state, u8 *m, u64 *mlen, const u8 *c, u64 clen,  const unsigned char *k){
    clen -= CRYPTO_ABYTES;
    *mlen = clen;
    if (clen != 0){
        while (clen > BYTE(RATE)){
            for(int i=0; i<BYTE(RATE); i++)
                m[i]=c[i];
            rho2((uint32_t*)(m), state);
            rhop1(state, (uint32_t*)(c));
            RATEWHITENING(state);
            sparklePermutation(state, STEPSSLIM);
            clen -= BYTE(RATE); m += BYTE(RATE); c += BYTE(RATE);
        }
        uint32_t lBlock[WORD(RATE)];
        pad(lBlock, (u8 *)(c), clen);
        rho2(lBlock, state);
        memcpy(m, lBlock, clen);
        if (clen < BYTE(RATE)){
            pad(lBlock, m, clen);
            rho1(state, lBlock);
            INJECTCONST(state, PADPTCONST);
            RATEWHITENING(state);
            sparklePermutation(state, STEPSBIG);
        }
        else {
            rhop1(state, (uint32_t *)(c));
            INJECTCONST(state, NOPADPTCONST);
            RATEWHITENING(state);
            sparklePermutation(state, STEPSBIG);
        }
    }
    c+=clen; 
    for(int i=0; i<CRYPTO_ABYTES; i++){ 
        ((uint8_t *)(state) + BYTE(RATE) )[i] ^= k[i];
    }

    if (verifyTag(state, (u8 *)(c)) == 0)
        return 0;
    else{
        #ifndef _DEBUG
            for (unsigned long long i=0; i < *mlen; i++) m[i]=0;
        #endif
        return -1;
    }
}



int crypto_aead_encrypt(
unsigned char *c,unsigned long long *clen,
const unsigned char *m,unsigned long long mlen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k
)
{
    #ifdef _DEBUG
        uint32_t state[WORD(STATESIZE)]={0};
    #else
        uint32_t state[WORD(STATESIZE)];
    #endif
    initialize(state, k, npub);
    processAD(state, ad, adlen);
    encryptPT(state, c, clen, m, mlen, k);

    return 0;
}

int crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
    int decSucess;
    uint32_t state[WORD(STATESIZE)];
    initialize(state, k, npub);
    processAD(state, ad, adlen);
    decSucess = decryptCT(state, m, mlen, c, clen, k);
    return decSucess;
}

