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
#define SHA256_BLOCK_LENGTH 64
#define AES_KEY_LENGTH 32
#define RANDOM_STRING_LENGTH 32
#define RSA_KEY_LENGTH 2048	/* bit */
#define RSA_KEY_EXP 3

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
	AES_KEY aesKey;
	unsigned char *aesOut;
    unsigned char encIv[AES_BLOCK_SIZE];    /* initialization vector for AES encryption */
    unsigned char decIv[AES_BLOCK_SIZE];    /* initialization vector for AES decryption */
	RSA *keypair;	/* public/private key pair */
	BIO *pub;
	size_t pubLen;
	unsigned char *pubKey;
	unsigned char sessionKey[AES_KEY_LENGTH];
	unsigned char randomA[RANDOM_STRING_LENGTH];
	unsigned char randomB[RANDOM_STRING_LENGTH];
	unsigned char msg[512];	/* message from server */
	size_t msgLen;	/* length of message from server */

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
	getDigest(digest, salt, password);

	/* generate public/private key pair for RSA */
	keypair = RSA_generate_key(RSA_KEY_LENGTH, RSA_KEY_EXP, NULL, NULL);

	/* extract public key from key pair */
	pub = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(pub, keypair);
	pubLen = BIO_pending(pub);
	pubKey = (unsigned char *) malloc(pubLen + 1);
    BIO_read(pub, pubKey, pubLen);
	pubKey[pubLen] = '\0';

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
	AES_set_encrypt_key(digest, SHA256_DIGEST_LENGTH*8, &aesKey);
    AES_cbc_encrypt(pubKey, aesOut, pubLen, &aesKey, encIv, AES_ENCRYPT);
    /**********************************
     * send aesOut (pubKey) to server *
     **********************************/

    /*********************************************
     * receive encrypted session key from server *
     *********************************************/
    /* decrypt the message and get session key */
    msgLen = strlen(msg);
    RSA_private_decrypt(RSA_size(keypair), msg, sessionKey, keypair, RSA_PKCS1_OAEP_PADDING);

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
    AES_set_encrypt_key(sessionKey, AES_KEY_LENGTH*8, &aesKey);
    AES_cbc_encrypt(randomA, aesOut, RANDOM_STRING_LENGTH, &aesKey, encIv, AES_ENCRYPT);

    /***********************************
     * send aesOut (randomA) to server *
     ***********************************/

	/*************************************************
     * receive encrypted randomA+randomB from server *
     *************************************************/
    /* decrypt the message and get random string A and B */
    aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH*2);
    AES_set_decrypt_key(sessionKey, AES_KEY_LENGTH*8, &aesKey);
    AES_cbc_encrypt(msg, aesOut, RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE, &aesKey, decIv, AES_DECRYPT);

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
    AES_set_encrypt_key(sessionKey, AES_KEY_LENGTH*8, &aesKey);
    AES_cbc_encrypt(randomB, aesOut, RANDOM_STRING_LENGTH, &aesKey, encIv, AES_ENCRYPT);
    /***********************************
     * send aesOut (randomB) to server *
     ***********************************/

    RSA_free(keypair);
    BIO_free_all(pub);
    free(pubKey);
    free(aesOut);
}
