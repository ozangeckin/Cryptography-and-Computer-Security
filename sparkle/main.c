#include "crypto_aead.h"
#include <stdio.h>
#include <string.h>

#define CRYPTO_BYTES 64
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1



void string2hexString(unsigned char* input, int clen, char* output);
void *hextobyte(char *hexstring, unsigned char* bytearray );

int main (int argc, char *argv[]) {


  unsigned long long mlen;
  unsigned long long clen;

  unsigned char plaintext[CRYPTO_BYTES];
  unsigned char cipher[CRYPTO_BYTES]; 
  unsigned char npub[CRYPTO_NPUBBYTES]="";
  unsigned char ad[CRYPTO_ABYTES]="";
  unsigned char nsec[CRYPTO_ABYTES]="";
  
  unsigned char key[CRYPTO_KEYBYTES];

  char pl[CRYPTO_BYTES]="GEBZE TECHNICAL UNIVERSITY";
  char chex[CRYPTO_BYTES]="";
  char keyhex[2*CRYPTO_KEYBYTES+1]="0123456789ABCDEF0123456789ABCDEF";
  char nonce[2*CRYPTO_NPUBBYTES+1]="000000000000111111111111";
   char add[CRYPTO_ABYTES]="";

  if( argc > 1 ) {
      strcpy(pl,argv[1]);
  }
  if( argc > 2 ) {
      strcpy(keyhex,argv[2]);
  }
    if( argc > 3 ) {
      strcpy(nonce,argv[3]);
  }
     if( argc > 4 ) {
      strcpy(add,argv[4]);
  }
  

  if (strlen(keyhex)!=32) {
	printf("Key length needs to be 16 bytes");
	return(0);
  }

  strcpy(plaintext,pl);
  strcpy(ad,add);
  hextobyte(keyhex,key);
  hextobyte(nonce,npub);

  printf("SPARKLE AEAD light-weight cipher\n");
  printf("Plaintext: %s\n",plaintext);
  printf("Key: %s\n",keyhex);
  printf("Nonce: %s\n",nonce);
  printf("Additional Information: %s\n\n",ad);

  printf("Plaintext: %s\n",plaintext);


  int ret = crypto_aead_encrypt(cipher,&clen,plaintext,strlen(plaintext),ad,strlen(ad),nsec,npub,key);


string2hexString(cipher,clen,chex);

  printf("Cipher: %s, Len: %llu\n",chex, clen);



  ret = crypto_aead_decrypt(plaintext,&mlen,nsec,cipher,clen,ad,strlen(ad),npub,key);

  plaintext[mlen]='\0';
  printf("Plaintext: %s, Len: %llu\n",plaintext, mlen);




  if (ret==0) {
    printf("Success!\n");
  }  
 
	return 0;
} 
void string2hexString(unsigned char* input, int clen, char* output)
{
    int loop;
    int i; 
    
    i=0;
    loop=0;
    
    for (i=0;i<clen;i+=2){
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;

    }
    output[i++] = '\0';
}
void *hextobyte(char *hexstring, unsigned char* bytearray ) {

    int i;

    int str_len = strlen(hexstring);

    for (i = 0; i < (str_len / 2); i++) {
        sscanf(hexstring + 2*i, "%02hhx", &bytearray[i]);
    }

}

