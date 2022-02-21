#ifndef UTIL_H
#define UTIL_H

#include "stdint.h"
#include "schwaemmconfig.h"

#ifdef _DEBUG
    #define INLINE
#else
    #define INLINE inline
#endif /*_DEBUG*/

#define u8 unsigned char
#define u64 long long unsigned int

#define WORDSIZE (32)
#define BYTE(X) (X/8)
#define WORD(X) (X/WORDSIZE)
#define ROT32(x, n) ((x >> n) | (x << (WORDSIZE-n)))
#define INJECTCONST(x, y) x[WORD(STATESIZE)-1] ^= (y) << 24

#define SWAPu32(X, Y, TMP) {TMP = X; X=Y; Y=TMP;}

#define RATEWHITENING(S) do{                          \
    for(int _i=0; _i<WORD(RATE); _i++){               \
        S[_i] ^= S[(WORD(RATE))+(_i%(WORD(CAPACITY)))];   \
    }                                                 \
}while(0)

#define ELL(x) do{                                                             \
    x ^= x << 16;                                                              \
    x = ROT32(x, 16);                                                          \
}while(0)

extern const uint32_t C_SEED[8];

uint32_t load32( unsigned char *in);
    void store32(unsigned char *out, uint32_t in);
    void feistelSwap(uint32_t *state);
    void rho1(uint32_t *state, uint32_t *D);
    void rho2(uint32_t *state, uint32_t *D);
    void rhop1(uint32_t *state, uint32_t *D);
    void pad(uint32_t *out, u8 *in, u8 inlen);
    void sparklePermutation(uint32_t state[WORD(STATESIZE)], int Ns);

#endif /*UTIL_H*/

