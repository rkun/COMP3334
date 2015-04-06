/*
	1. Alice generates public/private key pair unique for the session Pa (private) and P'a (public) Alice encrypts public key using S and sends it to Bob.

	2. Bob (knowing S) decrypts Alices message and recovers Alice's public key P'a. Bob generates random session key K. Bob encrypts K with Alice's public key P'a and sends it to Alice.

	3. Alice decrypts the message and obtains K. Alice generates random string Ra, encrypts it with K and sends to bob

	4. Bob decrypts the message to obtain Ra, generates another random Rb, encrypts both with K and sends the encrypted message to Alice.

	5. Alice decrypts message, verifies her own Ra being valid in the message. She encrypts only Rb with K and sends to Bob.

	6. Bob decrypts Rb and verifies his own Rb being valid.
*/

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define SALT_LEN 32
#define RANDOM_STRING_LENGTH 32
#define RSA_KEY_LENGTH 2048	/* bit */
#define RSA_KEY_EXP 3
#define RSA_PADDING RSA_PKCS1_OAEP_PADDING

void encryptWithAES(unsigned char* output, unsigned char* input, int inputLen, unsigned char* iv, unsigned char* key, int keyLen)
{   /* inputLen and keyLen are in bytes */
    AES_KEY aesKey;
    AES_set_encrypt_key(key, keyLen*8, &aesKey);
    AES_cbc_encrypt(input, output, inputLen, &aesKey, iv, AES_ENCRYPT);
}

void decryptWithAES(unsigned char* output, unsigned char* input, int inputLen, unsigned char* iv, unsigned char* key, int keyLen)
{   /* inputLen and keyLen are in bytes */
    AES_KEY aesKey;
    AES_set_decrypt_key(key, keyLen*8, &aesKey);
    AES_cbc_encrypt(input, output, inputLen, &aesKey, iv, AES_DECRYPT);
}

int extractRSAPubKey(unsigned char* pubKey, RSA* keypair)
{
    BIO* pub;
    int pubKeyLen;

    pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, keypair);
    pubKeyLen = BIO_pending(pub);
    BIO_read(pub, pubKey, pubKeyLen);
    pubKey[pubKeyLen] = '\0';

    BIO_free_all(pub);
    return pubKeyLen;   /* return the size of public key */
}

int decryptWithRSAPriKey(unsigned char* output, unsigned char* input, RSA* keypair)
{
    return RSA_private_decrypt(RSA_size(keypair), input, output, keypair, RSA_PADDING); /* return the size of recovered plaintext */
}

void getDigest(unsigned char* digest, unsigned char* salt, char* password)
{
	int pwlength = strlen(password);
	int totalLength = SALT_LEN + pwlength;
	unsigned char pwAndSalt[totalLength];

	/* append salt to password */
	memcpy(pwAndSalt, password, pwlength);
	memcpy(pwAndSalt + pwlength, salt, SALT_LEN);

	/* hash the appended value (passwordsalt) */
	SHA256((unsigned char*)pwAndSalt, totalLength, digest);
}

int main(int argc, char *argv[])
{
	unsigned char salt[SALT_LEN];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned char *aesOut; /* output of AES encryption / decryption */
    unsigned char encIv[AES_BLOCK_SIZE];    /* initialization vector for AES encryption */
    unsigned char decIv[AES_BLOCK_SIZE];    /* initialization vector for AES decryption */
	RSA *keypair;	/* public/private key pair */
	unsigned char pubKey[RSA_KEY_LENGTH/8*2];
    int pubKeyLen;
	unsigned char sessionKey[32]; /* max AES key length is 256-bit */
    int sesKeyLen;
	unsigned char randomA[RANDOM_STRING_LENGTH];
	unsigned char randomB[RANDOM_STRING_LENGTH];
	unsigned char msg[512];	/* message from server */

	/****************************************
	 * read username and password from user *
	 ****************************************/

	/***************************
	 * send username to server *
	 ***************************/

	/****************************
	 * receive salt from server *
	 ****************************/

	/* generate hash of password+salt */
	getDigest(digest, salt, /* password */);

	/* generate public/private key pair for RSA */
	keypair = RSA_generate_key(RSA_KEY_LENGTH, RSA_KEY_EXP, NULL, NULL);

	/* extract public key from key pair */
    pubKeyLen = extractRSAPubKey(pubKey, keypair);


	/* generate encIv for AES encryption of public key */
	RAND_bytes(encIv, AES_BLOCK_SIZE);
	/***********************************
     * send encIv for pubKey to server *
     ***********************************/

    /*************************************
     * wait for confirmation message (?) *
     *************************************/

	/* AES encrypt with digest and send public key to server */
    aesOut = (unsigned char *) malloc(RSA_KEY_LENGTH/8*2);
    encryptWithAES(aesOut, pubKey, pubKeyLen, encIv, digest, SHA256_DIGEST_LENGTH);
    /**********************************
     * send aesOut (pubKey) to server *
     **********************************/

    /*********************************************
     * receive encrypted session key from server *
     *********************************************/
    /* decrypt the message and get session key */
    sesKeyLen = decryptWithRSAPriKey(sessionKey, msg, keypair);

    /* generate randomA */
    RAND_bytes(randomA, RANDOM_STRING_LENGTH);

    /* generate encIv for AES encryption of randomA */
	RAND_bytes(encIv, AES_BLOCK_SIZE);

    /************************************
     * send encIv for randomA to server *
     ************************************/

    /*************************************************
     * receive decIv for randomA+randomB from server *
     *************************************************/

    /* AES encrypt with session key and send randomA to server */
    aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE);
    encryptWithAES(aesOut, randomA, RANDOM_STRING_LENGTH, encIv, sessionKey, sesKeyLen);

    /***********************************
     * send aesOut (randomA) to server *
     ***********************************/

	/*************************************************
     * receive encrypted randomA+randomB from server *
     *************************************************/
    /* decrypt the message and get random string A and B */
    aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH*2);
    decryptWithAES(aesOut, msg, RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE, decIv, sessionKey, sesKeyLen);

    /* Verify randomA */
    if (memcmp(randomA, aesOut, RANDOM_STRING_LENGTH) != 0)
    {
    	printf("Invalid Random String!\n");
    	exit(1);
    }

    /* get randomB */
    memcpy(randomB, aesOut+RANDOM_STRING_LENGTH, RANDOM_STRING_LENGTH);

    /* generate encIv for AES encryption of randomB */
	RAND_bytes(encIv, AES_BLOCK_SIZE);
	/************************************
     * send encIv for randomB to server *
     ************************************/

    /*************************************
     * wait for confirmation message (?) *
     *************************************/

    /* AES encrypt with session key and sned randomB back to server */
    aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE);
    encryptWithAES(aesOut, randomB, RANDOM_STRING_LENGTH, encIv, sessionKey, sesKeyLen);
    /***********************************
     * send aesOut (randomB) to server *
     ***********************************/

    RSA_free(keypair);
    free(aesOut);
}
