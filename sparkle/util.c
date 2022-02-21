#include "stdint.h"
#include "util.h"
#include "schwaemmconfig.h"
#include "string.h"
#include "sparkle.h"

const uint32_t C_SEED[8] = {0xB7E15162, 0x8AED2A6A, 0xBF715880, 0x9CF4F3C7, 0x62E7160F, 0x38B4DA56, 0xA784D904, 0x5190CFEF};

uint32_t load32( unsigned char *in){
    uint32_t out;
    memcpy (&out, in, sizeof(out));
    return out;
}

void store32(unsigned char *out, uint32_t in){
     memcpy (out, &in, sizeof(in));
}

void feistelSwap(uint32_t *state){
    uint32_t tmp;
    for(int i=0; i<WORD(RATE/2); i++){
        tmp = state[i];
        state[i] = state[WORD(RATE/2)+i];
        state[WORD(RATE/2)+i] ^= tmp;
    }
}

void rho1(uint32_t *state, uint32_t *D){
    feistelSwap(state);
    for(int i=0; i<WORD(RATE); i++)
        state[i] ^= D[i];
}

void rho2(uint32_t *state, uint32_t *D){ 
    for(int i=0; i<WORD(RATE); i++)
        state[i] ^= D[i];
}

void rhop1(uint32_t *state, uint32_t *D){ 
    uint32_t tmp[BYTE(RATE)];
    memcpy (tmp, state, BYTE(RATE));
    feistelSwap(state);
    for(int i=0; i<WORD(RATE); i++)
        state[i] ^= D[i] ^ tmp[i];
}


void pad(uint32_t *out, u8 *in, u8 inlen){
  
    memcpy(out, in, inlen);
    uint8_t *o;
    o=(uint8_t *)(out);
    if (inlen!=BYTE(RATE)){
        o[inlen]=0x80;
        memset(o+inlen+1, 0, BYTE(RATE)-inlen-1);
    }
}
void sparklePermutation(uint32_t state[WORD(STATESIZE)], int Ns){
    state_t S={{0},{0}};
    for (int i=0; i<B*2; i++){
        S.x[i] = state[2*i];
        S.y[i] = state[2*i+1];
    }

    sparkle_ref(&S, B*2, Ns); 

    for (int i=0; i<B*2; i++){
        state[2*i]   = S.x[i];
        state[2*i+1] = S.y[i];
    }

}

