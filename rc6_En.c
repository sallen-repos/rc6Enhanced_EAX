#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>


#define W 32 //word size
#define H_W 16 //Half word size

#define P_W 0xB7E15163 // The first 'magic' constant - defined as Odd((e-2)*2^{w}) where Odd is the nearest odd integer to W, and e is the base of the natural logarithm
#define Q_W 0x9E3779B9 // The second 'magic' constant -  defined as  Odd((phi - 1) * 2^w) where Odd is the nearest odd integer to W, and phi is the golden ratio
#define LG_W 5 //Log W

#define ROUNDS      20      // Default number of rounds
#define KEY_LENGTH  256     // Key Length in bits
#define WORD_LENGTH 32      // Word length in bits
#define TEXT_LENGTH 8

const int8_t CONSTANT = 0x8D;

#define MASK ((unsigned char)(128))

typedef struct cypherContext
{
    unsigned char rounds;  // The number of rounds executed when encrypting data
    uint32_t *subKeyWord;    // The round subkey words
}

cypherContext;
cypherContext* setNewContext();

// Delete current context
void freeContext(cypherContext *context);

// Key Expansion Algorithm
void keyExpansion(cypherContext *context, void *key);

// Encryption Algorithm
void encrypt(cypherContext *context, void *block);

// Decryption Algorithm
void decrypt(cypherContext *context, void *block);

//shift rotate left n spaces
uint32_t rotateLeft(uint32_t a, unsigned char n);

//shift rotate left n spaces
uint32_t rotateRight(uint32_t a, unsigned char n);


cypherContext* setNewContext()
{
    cypherContext *newContext = malloc(sizeof(cypherContext));
    newContext->subKeyWord = (uint32_t*) calloc(2*ROUNDS+4, sizeof(uint32_t));
    newContext->rounds = ROUNDS;
    return newContext;
}

void freeContext(cypherContext *context)
{
    free(context->subKeyWord);
    free(context);
}


void keyExpansion(cypherContext *context, void *key)
{
    context->subKeyWord[0] = P_W;
    unsigned char i = 0, j = 0;
    for(i = 1; i <= 2*context->rounds+3; ++i)
        context->subKeyWord[i] = context->subKeyWord[i-1] + Q_W;

    i = 0;
    uint32_t a = 0, b = 0, X = 0, Y = 0;
    for(unsigned char k=1; k<=3*(2*context->rounds+4); ++k)
    {
        a = context->subKeyWord[i] = rotateLeft((context->subKeyWord[i] + a + b), 3);
        b = ((uint32_t*)key)[j] = rotateLeft(((uint32_t*)key)[j] + a + b, a + b);
        i = (i+1) % (2*context->rounds+4);
        j = (j+1) % (KEY_LENGTH/WORD_LENGTH);
    }
}

uint32_t rotateLeft(uint32_t value, unsigned char offset)
{
	return (value << offset) | (value >> (W - offset));
}

uint32_t rotateRight(uint32_t value, unsigned char offset)
{
	return (value >> offset) | (value << (W - offset));
}

void encrypt(cypherContext *context, void* block)
{
    uint32_t A = ((uint32_t *)block)[0];
    uint32_t B = ((uint32_t *)block)[1];
    uint32_t C = ((uint32_t *)block)[2];
    uint32_t D = ((uint32_t *)block)[3];
	uint32_t E = ((uint32_t *)block)[4];
	uint32_t F = ((uint32_t *)block)[5];
	uint32_t G = ((uint32_t *)block)[6];
	uint32_t H = ((uint32_t *)block)[7];

    B += context->subKeyWord[0];
    D ^= context->subKeyWord[0];
	F += context->subKeyWord[1];
	H ^= context->subKeyWord[1];

    uint32_t fOne=0, fTwo=0, rOne=0,rTwo=0, tempRegister;
    for(unsigned char i = 1; i <= context->rounds; ++i)
    {
		fOne = (B * B) + (F * F) - (B * F) - 7;
		fTwo = (D * D) + (H * H) - (D * H) - 7;
		
		rOne = rotateLeft(fOne, fTwo);
		rTwo = rotateLeft(fTwo, fOne);

		A = rotateLeft((A ^ rOne), rTwo) + context->subKeyWord[2 * i];        
		C = rotateLeft((C + rTwo), rOne) ^ context->subKeyWord[2 * i];
		E = rotateLeft((E ^ rOne), rTwo) + context->subKeyWord[2 * i + 1];
		G = rotateLeft((G + rTwo), rOne) ^ context->subKeyWord[2 * i + 1];

		tempRegister = A;
        A = B;
        B = C;
        C = D;
		D = E;
		E = F;
		F = G;
		G = H;
		H = tempRegister;
    }

    A += context->subKeyWord[ 2 * context->rounds + 2];
    C ^= context->subKeyWord[ 2 * context->rounds + 2];
	E += context->subKeyWord[ 2 * context->rounds + 3];
	G ^= context->subKeyWord[ 2 * context->rounds + 3];

    ((uint32_t *)block)[0] = A;
    ((uint32_t *)block)[1] = B;
    ((uint32_t *)block)[2] = C;
    ((uint32_t *)block)[3] = D;
	((uint32_t *)block)[4] = E;
	((uint32_t *)block)[5] = F;
	((uint32_t *)block)[6] = G;
	((uint32_t *)block)[7] = H;
}



void decrypt(cypherContext *context, void *block)
{
	uint32_t A = ((uint32_t *)block)[0];
	uint32_t B = ((uint32_t *)block)[1];
	uint32_t C = ((uint32_t *)block)[2];
	uint32_t D = ((uint32_t *)block)[3];
	uint32_t E = ((uint32_t *)block)[4];
	uint32_t F = ((uint32_t *)block)[5];
	uint32_t G = ((uint32_t *)block)[6];
	uint32_t H = ((uint32_t *)block)[7];

    C ^= context->subKeyWord[2 * context->rounds + 2];
    A -= context->subKeyWord[2 * context->rounds + 2];
	G ^= context->subKeyWord[2 * context->rounds + 3];
	E -= context->subKeyWord[2 * context->rounds + 3];
	
	uint32_t fOne = 0, fTwo = 0, rOne = 0, rTwo = 0, tempRegister;
    for(unsigned char i = context->rounds; i > 0; --i)
    {
        tempRegister = H;
		H = G;
		G = F;
		F = E;		
		E = D;
        D = C;
        C = B;
        B = A;
        A = tempRegister;

		fOne = (B * B) + (F * F) - (B * F) - 7;
		fTwo = (D * D) + (H * H) - (D * H) - 7;
       
		rOne = rotateLeft(fOne, fTwo);
		rTwo = rotateLeft(fTwo, fOne);

		A = rotateRight((A - context->subKeyWord[2 * i]), rTwo) ^ rOne;
        C = rotateRight((C ^ context->subKeyWord[2 * i]), rOne) - rTwo;
		E = rotateRight((E - context->subKeyWord[2 * i + 1]), rTwo) ^ rOne;
		G = rotateRight((G ^ context->subKeyWord[2 * i + 1]), rOne) - rTwo;
    }

	D ^= context->subKeyWord[0];
	B -= context->subKeyWord[0];   	 
	H ^= context->subKeyWord[1];
    F -= context->subKeyWord[1];
		
	((uint32_t *)block)[0] = A;
	((uint32_t *)block)[1] = B;
	((uint32_t *)block)[2] = C;
	((uint32_t *)block)[3] = D;
	((uint32_t *)block)[4] = E;
	((uint32_t *)block)[5] = F;
	((uint32_t *)block)[6] = G;
	((uint32_t *)block)[7] = H;
}

unsigned char * encryptionRound(unsigned char *key, unsigned char *text)
{
	cypherContext *p = setNewContext();
	keyExpansion(p, key);
	encrypt(p, text);

	return key;
	
}


void cypherText(unsigned char *key, unsigned char *text)
{
	cypherContext *contextPointer = setNewContext();

	keyExpansion(contextPointer, key);

	encrypt(contextPointer, text);

	POINT point;
	
	for (int i = 0; i < H_W; ++i)
	{
		if (text[i] > TEXT_LENGTH)

			printf("%c", text[i]);
	}

	GetCursorPos(&point);
	printf("\n");

	decrypt(contextPointer, text);
	for (int i = 0; i < H_W; ++i)
	{
		if (text[i] > TEXT_LENGTH)

			printf("%c", text[i]);
	}

	SetCursorPos(point.x, point.y);


}

int mostSignificantBit(unsigned char value) {

//unsigned char mask = 0;

unsigned char i = (unsigned char) value & MASK;

printf("MASK=%d\n",i);

if (value & MASK == 0){
        return 0;
    }
else 
    return 1;
}

void shiftLeft(unsigned char * array, unsigned char * shiftedArray) {

for(int i = 0; i < 16; ++i)
   shiftedArray[i] = array[i] >> 1;

}

unsigned char * shiftXor(unsigned char * array, unsigned char * xorArray) {

for(int i = 0; i < 16; ++i)
   xorArray[i] = (array[i] >> 1) ^ CONSTANT;

}

void omac(unsigned char *key) {

	unsigned char L[16] = {0};
	
	printf("Zeros[0]=%d\n", L[0]);

	encryptionRound(key, L);


	printf("L=%d\n", L[0]);



	//printf("%d\n", mostSignificantBit(L[0]));
	//printf("%s\n", zeros);	

	unsigned char subKeyOne[16], subKeyTwo[16];

	const unsigned char CONSTANT;

	if (mostSignificantBit(L[0]) == 0) {
		
		shiftLeft(L, subKeyOne);		
	}
	else
	{
		shiftXor(L, subKeyOne);		
	}
	printf("L=%s\n", L);
	printf("subKeyOne=%s\n", subKeyOne);

	if (mostSignificantBit(subKeyOne) == 0) {

		shiftLeft(subKeyOne, subKeyTwo);		
	}
	else
	{
		shiftXor(subKeyOne, subKeyTwo);	
	}
	printf("L=%s\n", L);
	printf("subKeyOne=%s\n", subKeyOne);
	printf("subKeyTwo=%s\n", subKeyTwo);

	system("pause");
}

int main(void)
{	   
	unsigned char key[32] = {
		0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
		0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78,
		0x89,0x9A,0xAB,0xBC,0xCD,0xDE,0xEF,0xF0,
		0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE
	};	
	unsigned char str[32];
	unsigned int c;
		
	int i = 0;
/*
	while ((c = getc(stdin)) != '\n') {

		str[i++] = c;
		
		if (i >= H_W) {
			i = 0;

			cypherText(key, str);			
		}
	}
	while (i <= H_W) {

		str[i++] = '\n';
	}
	cypherText(key, str);
	
	*/

	omac(key);


	

	return 0;
}