/*
	1. Alice generates public/private key pair unique for the session Pa (private) and P'a (public) Alice encrypts public key using S and sends it to Bob.

	2. Bob (knowing S) decrypts Alices message and recovers Alice's public key P'a. Bob generates random session key K. Bob encrypts K with Alice's public key P'a and sends it to Alice.

	3. Alice decrypts the message and obtains K. Alice generates random string Ra, encrypts it with K and sends to bob

	4. Bob decrypts the message to obtain Ra, generates another random Rb, encrypts both with K and sends the encrypted message to Alice.

	5. Alice decrypts message, verifies her own Ra being valid in the message. She encrypts only Rb with K and sends to Bob.

	6. Bob decrypts Rb and verifies his own Rb being valid.
*/

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define AES_KEY_LENGTH 32
#define RANDOM_STRING_LENGTH 32
#define RSA_KEY_LENGTH 2048	/* bit */
#define RSA_KEY_EXP 3

void readSalt(unsigned char* salt, char* username, FILE* inputFile)
{
	size_t usernameLen = strlen(username);
	char buffer[130];
	int temp;
	ssize_t nByte;

	while (fread(buffer, usernameLen, 1, inputFile) == 1)
	{
		/* search for the username in users.txt */
		if (strncmp(buffer, username, strlen(username)) == 0)
		{
			temp = fgetc(inputFile);
			if (temp == '|')
			{
				/* username found, read the salt */
				fread(salt, SALT_LEN, 1, inputFile);
				return;
			}
			else
				/* username is not in the current line, go to next line */
				fgets(buffer, 130, inputFile);
		}
		else
		{
			/* username is not in the current line, go to next line */
			temp = fgetc(inputFile);
			if (temp != '\n')
			{
				ungetc(temp, inputFile);
				fgets(buffer, 130, inputFile);
			}
		}
	}

	printf("Invalid Username\n");
	exit(0);
}

void readDigest(unsigned char* digest, FILE* inputFile)
{
	fgetc(inputFile);
	fread(digest, SHA256_DIGEST_LENGTH, 1, inputFile);
}

int main(int argc, char *argv[])
{
	unsigned char salt[SALT_LEN];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	AES_KEY aesKey;
	unsigned char *aesOut;
	unsigned char encIv[AES_BLOCK_SIZE];    /* initialization vector for AES encryption */
    unsigned char decIv[AES_BLOCK_SIZE];    /* initialization vector for AES decryption */
	RSA *keypair;	/* public/private key pair */
	BIO *keybio;
	int rsaEncLen;
	unsigned char *rsaOut;
	unsigned char *pubKey;
	unsigned char sessionKey[AES_KEY_LENGTH];
	unsigned char randomA[RANDOM_STRING_LENGTH];
	unsigned char randomB[RANDOM_STRING_LENGTH];
	unsigned char randomAnB[RANDOM_STRING_LENGTH*2];
	unsigned char msg[512];	/* message from server */
	size_t msgLen;	/* length of message from server */

	/********************************
	 * receive username from client *
	 ********************************/

	/* get salt and send to client */
	readSalt(salt, /* username */, /* inputFile */);
	/***********************
	 * send salt to client *
	 ***********************/

	/********************************************
     * receive decIv for public key from client *
     ********************************************/

    /*********************************
     * send confirmation message (?) *
     *********************************/

    /********************************************
     * receive encrypted public key from client *
     ********************************************/
    /* decrypt the message and get public key */
    pubKey = (unsigned char *) malloc(RSA_KEY_LENGTH/8);
    AES_set_decrypt_key(sessionKey, AES_KEY_LENGTH, &aesKey);
    AES_cbc_encrypt(msg, pubKey, AES_KEY_LENGTH+AES_BLOCK_SIZE, &aesKey, decIv, AES_DECRYPT);

    /* generate session key */
    RAND_bytes(sessionKey, AES_KEY_LENGTH);

    /* RSA encrypt with public key and send session key to client */
    keybio = BIO_new_mem_buf(sessionKey, -1);
    rsaOut = malloc(RSA_size(keypair));
    keypair = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    rsaEncLen = RSA_public_encrypt(strlen(sessionKey)+1, sessionKey, rsaOut, keypair, RSA_PKCS1_OAEP_PADDING);

    /***************************************
	 * send rsaOut (session key) to client *
	 ***************************************/

	/*****************************************
     * receive decIv for randomA from client *
     *****************************************/

    /* generate encIv for randomA+randomB and send to client */
    RAND_bytes(encIv, AES_BLOCK_SIZE);
    /********************************************
	 * send encIv for randomA+randomB to client *
	 ********************************************/

	/*****************************************
     * receive encrypted randomA from client *
     *****************************************/
    /* decrypt the message and get randomA */
    AES_set_decrypt_key(sessionKey, AES_KEY_LENGTH, &aesKey);
    AES_cbc_encrypt(msg, randomA, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE, &aesKey, decIv, AES_DECRYPT);

    /* generate randomB */
    RAND_bytes(randomB, RANDOM_STRING_LENGTH);

    /* merge randomA and randomB */
    strncpy(randomAnB, randomA, RANDOM_STRING_LENGTH);
    strncat(randomAnB, randomB, RANDOM_STRING_LENGTH);

    /* AES encrypt with session key and send randomAnB to client */
    aesOut = (unsigned char *) malloc(RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE);
    AES_set_encrypt_key(sessionKey, AES_KEY_LENGTH, &aesKey);
    AES_cbc_encrypt(randomAnB, aesOut, RANDOM_STRING_LENGTH*2, &aesKey, encIv, AES_ENCRYPT);
    /*************************************
     * send aesOut (randomAnB) to client *
     *************************************/

    /***************************************
     * receive decIv for randomB to server *
     ***************************************/

    /*********************************
     * send confirmation message (?) *
     *********************************/

	/*****************************************
     * receive encrypted randomB from client *
     *****************************************/
    /* decrypt the message and get randomB */
    aesOut = (unsigned char *) realloc(RANDOM_STRING_LENGTH);
    AES_set_decrypt_key(sessionKey, AES_KEY_LENGTH, &aesKey);
    AES_cbc_encrypt(msg, aesOut, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE, &aesKey, decIv, AES_DECRYPT);

    /* Verify randomA */
    if (strncmp(randomB, aesOut, RANDOM_STRING_LENGTH) != 0)
    {
    	printf("Invalid Random String!\n");
    	exit(1);
    }

    RSA_free(keypair);
    BIO_free_all(keybio);
    free(pubKey);
    free(aesOut);
    free(rsaOut);
}