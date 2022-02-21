/*   
    Author: OZAN GECKIN
			1801042103
*/   
#include <stdio.h> 
#include <string.h>  
#include <stdlib.h>

#define byte char

#define FrameBitsIV  0x10  
#define FrameBitsAD  0x30  
#define FrameBitsPC  0x50       
#define FrameBitsFinalization 0x70       

void stateUpdate(int *state, const char *key, int n);
void initialization(const char *key, const char *iv, int *state);
void processAssociatedData(const char *k, const char *ad, long long adlen, int *state);
int encryption(char *c,long int *clen, const char *m, long long mlen, const char *ad, long long adlen, const char *npub, const char *k);
int decryption(char *m, long long *mlen, const char *c, long long clen, const char *ad, long long adlen, const char *npub, const char *k);

void get_byte_array(const char *sourceText, byte *byteArray);
void xor_byte_arrays(const byte *in1, const byte *in2, byte *out,long BLOCK_SIZE);
void bytecpy(byte *dest, const byte *src,long BLOCK_SIZE); 
void CBCmode(const char* plain_text, const char* key, const char* IV, long block_n);
void OFBmode(const char* plain_text, const char* key, const char* IV, long block_n);


void stateUpdate(int *state, const char *key, int i) 
{
	int j;  
	int temp1, temp2, temp3, temp4, feedback; 
	for (j = 0; j < (i >> 5); j++)
	{
		temp1 = (state[1] >> 15) | (state[2] << 17);  
		temp2 = (state[2] >> 6)  | (state[3] << 26);  
		temp3 = (state[2] >> 21) | (state[3] << 11);     
		temp4 = (state[2] >> 27) | (state[3] << 5);  
		feedback = state[0] ^ temp1 ^ (~(temp2 & temp3)) ^ temp4 ^ ((int*)key)[j & 3];
		state[0] = state[1]; state[1] = state[2]; state[2] = state[3]; 
		state[3] = feedback ;
	}
}

void initialization(const char *key, const char *iv, int *state)
{
        int i;

		for (i = 0; i < 4; i++) state[i] = 0;     

		stateUpdate(state, key, 1024);  

        for (i = 0;  i < 3; i++)  
        {
			state[1] ^= FrameBitsIV;   
			stateUpdate(state, key, 384); 
			state[3] ^= ((int*)iv)[i]; 
		}   
}

void processAssociatedData(const char *k, const char *ad, long long adlen, int *state)
{
	long long i; 
	int j; 

	for (i = 0; i < (adlen >> 2); i++)
	{
		state[1] ^= FrameBitsAD;
		stateUpdate(state, k, 384);
		state[3] ^= ((int*)ad)[i];
	}

	if ((adlen & 3) > 0)
	{
		state[1] ^= FrameBitsAD;
		stateUpdate(state, k, 384);
		for (j = 0; j < (adlen & 3); j++)  ((char*)state)[12 + j] ^= ad[(i << 2) + j];
		state[1] ^= adlen & 3;
	}   
}     

int encryption(char *c,long int *clen, const char *m, long long mlen, const char *ad, long long adlen, const char *npub, const char *k)
{
	long long i;
	int j;
	char mac[8];
	int state[4];

	initialization(k, npub, state);

	processAssociatedData(k, ad, adlen, state);

	for (i = 0; i < (mlen >> 2); i++)
	{
		state[1] ^= FrameBitsPC;
		stateUpdate(state, k, 1024);
		state[3] ^= ((int*)m)[i];
		((int*)c)[i] = state[2] ^ ((int*)m)[i];
	}
	if ((mlen & 3) > 0)
	{
		state[1] ^= FrameBitsPC;
		stateUpdate(state, k, 1024);
		for (j = 0; j < (mlen & 3); j++)
		{
			((char*)state)[12 + j] ^= m[(i << 2) + j];
			c[(i << 2) + j] = ((char*)state)[8 + j] ^ m[(i << 2) + j];
		}
		state[1] ^= mlen & 3;
	}

	state[1] ^= FrameBitsFinalization;
	stateUpdate(state, k, 1024);
	((int*)mac)[0] = state[2];

	state[1] ^= FrameBitsFinalization;
	stateUpdate(state, k, 384);
	((int*)mac)[1] = state[2];

	*clen = mlen + 8;
	memcpy(c + mlen, mac, 8);

	return 0;
}

int decryption(char *m, long long *mlen, const char *c, long long clen, const char *ad, long long adlen, const char *npub, const char *k)
{
	long long i;
	int j, check = 0;
	char mac[8];
	int state[4];

	*mlen = clen - 8;

	initialization(k, npub, state);

	processAssociatedData(k, ad, adlen, state);

	for (i = 0; i < (*mlen >> 2); i++)
	{
		state[1] ^= FrameBitsPC;
		stateUpdate(state, k, 1024);
		((int*)m)[i] = state[2] ^ ((int*)c)[i];
		state[3] ^= ((int*)m)[i];
	}
	if ((*mlen & 3) > 0)
	{
		state[1] ^= FrameBitsPC;
		stateUpdate(state, k, 1024);
		for (j = 0; j < (*mlen & 3); j++)
		{
			m[(i << 2) + j] = c[(i << 2) + j] ^ ((char*)state)[8 + j];
			((char*)state)[12 + j] ^= m[(i << 2) + j];
		}
		state[1] ^= *mlen & 3;
	}

	state[1] ^= FrameBitsFinalization;
	stateUpdate(state, k, 1024);
	((int*)mac)[0] = state[2];

	state[1] ^= FrameBitsFinalization;
	stateUpdate(state, k, 384);
	((int*)mac)[1] = state[2];

	for (j = 0; j < 8; j++) { check |= (mac[j] ^ c[clen - 8 + j]); }
	if (check == 0) return 0;
	else return -1;
}

void get_byte_array(const char *sourceText, byte *byteArray) 
{
    int sourceLen = (int) strlen(sourceText);
    for (int i = 0; i < sourceLen; ++i) byteArray[i] = sourceText[i];
}

void xor_byte_arrays(const byte *in1, const byte *in2, byte *out,long BLOCK_SIZE) 
{
    for (int i = 0; i < BLOCK_SIZE; ++i) 
		out[i] = in1[i] ^ in2[i];
}

void bytecpy(byte *dest, const byte *src,long BLOCK_SIZE) 
{
    for (int i = 0; i < BLOCK_SIZE; ++i) 
		dest[i] = src[i];
}

void CBCmode(const char* plain_text, const char* key, const char* IV, long block_n)
{
	char plaintext[strlen(plain_text)+1];
	strcpy(plaintext, plain_text);
	int BLOCK_SIZE = strlen(plaintext)/block_n;
	long clens[block_n];
	char* associative_data = "assoc_data";
	long assoc_data_len  = sizeof(char)*strlen(associative_data);
	char* npub = "123456789012";

	int keyLen = (int)strlen(key);
    byte keyBytes[keyLen];
    get_byte_array(key, keyBytes);

    const int sourceLen = (int) strlen(plaintext);

    byte plaintextBytes[sourceLen];
    get_byte_array(plaintext, plaintextBytes);

    const int blockCount = sourceLen / BLOCK_SIZE + 1;
    byte byteBlocks[blockCount][BLOCK_SIZE*10];
	
	for (int i = 0; i < blockCount; ++i) {
        for (int j = 0; j < BLOCK_SIZE*10; ++j) {
            byteBlocks[i][j] = '\0';
        }
    }

    int bytePos = 0;
    for (int i = 0; i < blockCount; ++i) {
        for (int j = 0; j < BLOCK_SIZE; ++j) {
            byteBlocks[i][j] = plaintextBytes[bytePos++];
        }
    }

    int padding = bytePos - sourceLen;
    for (int i = BLOCK_SIZE - padding; i < BLOCK_SIZE*10; ++i) {
        byteBlocks[blockCount - 1][i] = '\0';
    }

	printf("\nCBC MODE :\n");
    printf("Test plaintext : %s\n", plaintext);
   
    for (int i = 0; i < blockCount; ++i) {
        byte tempStore[BLOCK_SIZE];

        if (i == 0) {
            xor_byte_arrays(IV, byteBlocks[i], tempStore, BLOCK_SIZE);
        } else {
            xor_byte_arrays(byteBlocks[i - 1], byteBlocks[i], tempStore, BLOCK_SIZE);
        }

		encryption(
				byteBlocks[i], &clens[i],
				tempStore, BLOCK_SIZE,
				associative_data,
				assoc_data_len,
				npub,
				key
			);   
    }

    printf("Test Encrypted CBC mode :");
    for (int i = 0; i < blockCount; ++i) {
        for (int j = 0; j < BLOCK_SIZE; ++j) {
            printf("%c", byteBlocks[i][j]);
        }
    }
    printf("\n");

    byte cipherStore[BLOCK_SIZE*10];
    for(int i =0; i<BLOCK_SIZE*10; ++i ) cipherStore[i] = '\0';
    bytecpy(cipherStore, byteBlocks[0], clens[0]);

    for (int i = 0; i < blockCount; ++i) {
        byte tempStore[BLOCK_SIZE], plainStore[BLOCK_SIZE];

		long long m_len;
		
		decryption(
			tempStore, &m_len,
			byteBlocks[i], clens[i],
			associative_data,assoc_data_len,
			npub,
			key
		);
        if (i == 0) {
            xor_byte_arrays(IV, tempStore, plainStore, BLOCK_SIZE);
        } else {
            xor_byte_arrays(cipherStore, tempStore, plainStore, BLOCK_SIZE);
        }
		plainStore[strlen(plainStore)] = '\0';
        bytecpy(cipherStore, byteBlocks[i], clens[i]);
        bytecpy(byteBlocks[i], plainStore, BLOCK_SIZE);
    }

    printf("Test Decrypted CBC mode :");
    for (int i = 0; i < blockCount; ++i) {
    	if( i == blockCount - 1){
    		printf("%s", byteBlocks[i]);
    	}else{
        for (int j = 0; j < BLOCK_SIZE; ++j) {
            printf("%c", byteBlocks[i][j]);
        }}
    }
	printf("\n");
}


void OFBmode(const char* plain_text, const char* key, const char* IV, long block_n)
{
	printf("\nOFB MODE : \n");
	printf("Test plaintext : %s\n",plain_text);

	int block_size = (strlen(plain_text)/block_n) + 1;
	byte text_blocks[block_n][block_size];
	for( int i =0; i<block_n; ++i ){
		for(int j = 0; j<block_size; ++j )
			text_blocks[i][j] = (byte)'\0';
	}
	for( int i =0; i<block_n; ++i ){
		for(int j = 0; j<block_size-1; ++j )
			text_blocks[i][j] = (byte)plain_text[i*block_size + j];
	}

	long clens[block_n];
	byte ciphere_key[block_n][block_size*10];
	byte ciphere_text[block_n][block_size*10];

	for( int i =0; i<block_n; ++i ){
		for(int j = 0; j<block_size*10; ++j ){
			ciphere_key[i][j] = (byte)'\0';
			ciphere_text[i][j] = (byte)'\0';
		}
	}
	char* associative_data = "assoc_data";
	long assoc_data_len  = sizeof(char)*strlen(associative_data);
	char* npub = "123456789012";
	
	for( int i = 0; i<block_n; ++i ){

		if( i == 0 ){
		encryption(
					ciphere_key[0], &clens[0],
					IV, strlen(IV)*sizeof(byte),
					associative_data,
					assoc_data_len,
					npub,
					key
				);  
		}
		else{
			encryption(
					ciphere_key[i], &clens[i],
					ciphere_key[i-1], strlen(IV)*sizeof(byte),
					associative_data,
					assoc_data_len,
					npub,
					key
				);
		}

		for(int j = 0; j<block_size; ++j ){
			if( j>clens[i] ){
				ciphere_text[i][j] = text_blocks[i][j] ^ ciphere_key[i][j%clens[i]];
			}
			else{
				ciphere_text[i][j] = ciphere_key[i][j] ^ text_blocks[i][j];
			}
		}
	}

	printf("Test Encrypted OFB mode : ");
	for(int i =0; i<block_n; ++i ){
		printf("%s", ciphere_text[i]);
	}
	printf("\n");

	printf("Test Decrypted OFB mode :");

	byte plain_text_deciphered[block_n][block_size];

	for( int i = 0; i<block_n; ++i ){

		for(int j =0; j<block_size; ++j ){
			if( j>clens[0] ){
				plain_text_deciphered[i][j] = ciphere_text[i][j] ^ ciphere_key[i][j%clens[i]];
			}
			else{
				plain_text_deciphered[i][j] = ciphere_key[i][j] ^ ciphere_text[i][j];
			}
		}
		printf("%s", plain_text_deciphered[i]);
	}
	printf("\n");
}

int main(){

	printf("PART A \n\n");
	printf("Test 1 File reading 'plaintext.txt'\n");
	char *filename = "plaintext.txt";
    FILE *fp = fopen(filename, "r");

    if (fp == NULL)
    {
        printf("Error: could not open file %s", filename);
        return 1;
    }

    const int MAX_LENGTH = 256;
    char buffer[MAX_LENGTH];
	char tempbuffer[MAX_LENGTH];
	memset( buffer, 0, MAX_LENGTH );
	memset( tempbuffer, 0, MAX_LENGTH );

    while (fgets(tempbuffer, MAX_LENGTH, fp))
        strcat(buffer,tempbuffer);
    fclose(fp);
	
	printf("Test 1 plaintext : %s",buffer);

	char* chiper = (char*)malloc(sizeof(char)*10000);
	long int chiperlen; 
	long long messagelen = strlen(buffer)*sizeof(char);
	char* associativeData = "assoc_data";
	long int associativeDatalen = sizeof(char)*strlen(associativeData);
	char* npub = "1234567890123456";
	char* key = "12345678901234567890123456789";

	encryption(chiper, &chiperlen,buffer, messagelen, associativeData, associativeDatalen, npub,key	);

	printf("Test 1 Encrypted : %s \n", chiper);
	printf("Test 1 Encrypted Length : %ld\n",chiperlen);

	char* decmessage = (char*)malloc(sizeof(char)*10000);
	long long decmessagelen;
	
	decryption(decmessage, &decmessagelen, chiper, chiperlen, associativeData, associativeDatalen, npub, key);
	printf("Test 1 Decrypted: %s\n", decmessage);



 	char* message= "Ozan GECKIN";
	char* chiper2 = (char*)malloc(sizeof(char)*10000);

	printf("Test 2 plaintext : %s\n",message);
	long long messagelen2 = strlen(message)*sizeof(char);
	long int chiperlen2; 
	encryption(chiper2, &chiperlen2, message, messagelen2, associativeData, associativeDatalen, npub, key);
	printf("Test 2 Encrypted : %s \n",chiper2);
	printf("Test 2 Encrypted Length : %ld\n",chiperlen2);

	char* decmessage2 = (char*)malloc(sizeof(char)*10000);
	long long decmessagelen2;
	
	decryption( decmessage2, &decmessagelen2, chiper2, chiperlen2,associativeData,associativeDatalen, npub, key);
	printf("Test 2 Decrypted: %s\n", decmessage2);

	printf("\nPART B\n");
	char* message2 = "GEBZETECHNICALUNIVERSITY";
	CBCmode(message2,key,npub,5);
	OFBmode(message2,key,npub,5);
}