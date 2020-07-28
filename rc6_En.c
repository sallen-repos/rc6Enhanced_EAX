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

typedef struct cypherContext
{
    uint8_t rounds;  // The number of rounds executed when encrypting data
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
uint32_t rotateLeft(uint32_t a, uint8_t n);

//shift rotate left n spaces
uint32_t rotateRight(uint32_t a, uint8_t n);


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
    uint8_t i = 0, j = 0;
    for(i = 1; i <= 2*context->rounds+3; ++i)
        context->subKeyWord[i] = context->subKeyWord[i-1] + Q_W;

    i = 0;
    uint32_t a = 0, b = 0, X = 0, Y = 0;
    for(uint8_t k=1; k<=3*(2*context->rounds+4); ++k)
    {
        a = context->subKeyWord[i] = rotateLeft((context->subKeyWord[i] + a + b), 3);
        b = ((uint32_t*)key)[j] = rotateLeft(((uint32_t*)key)[j] + a + b, a + b);
        i = (i+1) % (2*context->rounds+4);
        j = (j+1) % (KEY_LENGTH/WORD_LENGTH);
    }
}

uint32_t rotateLeft(uint32_t value, uint8_t offset)
{
	return (value << offset) | (value >> (W - offset));
}

uint32_t rotateRight(uint32_t value, uint8_t offset)
{
	return (value >> offset) | (value << (W - offset));
}

void encrypt(cypherContext *context, void* block)
{
    register uint32_t A = ((uint32_t *)block)[0];
    register uint32_t B = ((uint32_t *)block)[1];
    register uint32_t C = ((uint32_t *)block)[2];
    register uint32_t D = ((uint32_t *)block)[3];
	register uint32_t E = ((uint32_t *)block)[4];
	register uint32_t F = ((uint32_t *)block)[5];
	register uint32_t G = ((uint32_t *)block)[6];
	register uint32_t H = ((uint32_t *)block)[7];

    B += context->subKeyWord[0];
    D ^= context->subKeyWord[0];
	F += context->subKeyWord[1];
	H ^= context->subKeyWord[1];

    uint32_t F1=0, F2=0, R1=0,R2=0, tempRegister;
    for(uint8_t i = 1; i <= context->rounds; ++i)
    {
		F1 = (B * B) + (F * F) - (B * F) - 7;
		F2 = (D * D) + (H * H) - (D * H) - 7;
		
		R1 = rotateLeft(F1, F2);
		R2 = rotateLeft(F2, F1);

		A = rotateLeft((A ^ R1), R2) + context->subKeyWord[2 * i];        
		C = rotateLeft((C + R2), R1) ^ context->subKeyWord[2 * i];
		E = rotateLeft((E ^ R1), R2) + context->subKeyWord[2 * i + 1];
		G = rotateLeft((G + R2), R1) ^ context->subKeyWord[2 * i + 1];

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
	register uint32_t A = ((uint32_t *)block)[0];
	register uint32_t B = ((uint32_t *)block)[1];
	register uint32_t C = ((uint32_t *)block)[2];
	register uint32_t D = ((uint32_t *)block)[3];
	register uint32_t E = ((uint32_t *)block)[4];
	register uint32_t F = ((uint32_t *)block)[5];
	register uint32_t G = ((uint32_t *)block)[6];
	register uint32_t H = ((uint32_t *)block)[7];

    C ^= context->subKeyWord[2 * context->rounds + 2];
    A -= context->subKeyWord[2 * context->rounds + 2];
	G ^= context->subKeyWord[2 * context->rounds + 3];
	E -= context->subKeyWord[2 * context->rounds + 3];
	
	uint32_t F1 = 0, F2 = 0, R1 = 0, R2 = 0, tempRegister;
    for(uint8_t i = context->rounds; i > 0; --i)
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

		F1 = (B * B) + (F * F) - (B * F) - 7;
		F2 = (D * D) + (H * H) - (D * H) - 7;
       
		R1 = rotateLeft(F1, F2);
		R2 = rotateLeft(F2, F1);

		A = rotateRight((A - context->subKeyWord[2 * i]), R2) ^ R1;
        C = rotateRight((C ^ context->subKeyWord[2 * i]), R1) - R2;
		E = rotateRight((E - context->subKeyWord[2 * i + 1]), R2) ^ R1;
		G = rotateRight((G ^ context->subKeyWord[2 * i + 1]), R1) - R2;
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

void encryptionRound(unsigned char *key, unsigned char *text)
{
	cypherContext *p = setNewContext();
	keyExpansion(p, key);
	encrypt(p, text);
	
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

int main(void)
{	   
	unsigned char key[32] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89,0x9A,0xAB,0xBC,0xCD,0xDE,0xEF,0xF0,0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE };
	unsigned char str[32];
	unsigned int c;
		
	int i = 0;

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
	
	system("pause");

	return 0;
}
