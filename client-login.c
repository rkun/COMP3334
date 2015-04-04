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

#define SALT_LEN 32
#define SHA256_BLOCK_LENGTH 64
#define AES_KEY_LENGTH 32
#define RANDOM_STRING_LENGTH 32

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
	AES_KEY aesEncKey, aesDecKey;
	unsigned char *encOut, *decOut;
	unsigned char encIv[AES_BLOCK_SIZE], decIv[AES_BLOCK_SIZE];	/* initialization vector for AES */
	RSA *keypair;	/* public/private key pair */
	BIO *pub;
	size_t pubLen;
	unsigned char *pubKey;
	unsigned char rsaDecOut[RANDOM_STRING_LENGTH*2];
	unsigned char sessionKey[AES_KEY_LENGTH];
	unsigned char msg[512];
	size_t msgLen;
	unsigned char randomA[AES_KEY_LENGTH];
	unsigned char randomB[AES_KEY_LENGTH];

	/***************************
	 * read password from user *
	 ***************************/

	/****************************
	 * request salt from server *
	 ****************************/

	/****************************
	 * receive salt from server *
	 ****************************/

	/* generate hash of password+salt */
	getDigest(digest, salt, password);

	/* generate public/private key pair for RSA */
	keypair = RSA_generate_key(2048, 3, NULL, NULL);

	/* extract public key from key pair */
	pub = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(pub, keypair);
	pubLen = BIO_pending(pub);
	pubKey = malloc(pubLen + 1);
	pubKey[pubLen] = '\0';

	/* generate initialization vector for AES encryption of public key */
	RAND_bytes(encIv, AES_BLOCK_SIZE);
	/***********************************
     * send encIv for pubKey to server *
     ***********************************/

    /********************************
     * wait for confirm message (?) *
     ********************************/

	/* AES encrypt with digest and send public key to server */
    encOut = (unsigned char *) malloc(pubLen+AES_BLOCK_SIZE);
	AES_set_encrypt_key(digest, SHA256_DIGEST_LENGTH, &aesEncKey);
    AES_cbc_encrypt(pubKey, encOut, pubLen, &aesEncKey, encIv, AES_ENCRYPT);
    /**********************************
     * send encOut (pubKey) to server *
     **********************************/

    /********************************************
     * receive message (sessionKey) from server *
     ********************************************/
    /* decrypt the message and get session key */
    RSA_private_decrypt(msgLen, msg, sessionKey, keypair, RSA_PKCS1_OAEP_PADDING);

    /* generate a random string */
    RAND_bytes(randomA, RANDOM_STRING_LENGTH);

    /* generate initialization vector for AES encryption of randomA */
	RAND_bytes(encIv, AES_BLOCK_SIZE);
	/************************************
     * send encIv for randomA to server *
     ************************************/

    /*************************************************
     * receive decIv for randomA+randomB from server *
     *************************************************/

    /* AES encrypt with session key and send the random string to server */
    encOut = (unsigned char *) realloc(encOut, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE);
    AES_set_encrypt_key(sessionKey, AES_KEY_LENGTH, &aesEncKey);
    AES_cbc_encrypt(randomA, encOut, RANDOM_STRING_LENGTH, &aesEncKey, encIv, AES_ENCRYPT);
    /***********************************
     * send encOut (randomA) to server *
     ***********************************/

	/*************************************************
     * receive message (randomA+randomB) from server *
     *************************************************/
    /* decrypt the message and get random string A and B */
    decOut = (unsigned char *) malloc(RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE);
    AES_set_decrypt_key(sessionKey, AES_KEY_LENGTH, &aesDecKey);
    AES_cbc_encrypt(msg, decOut, RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE, &aesDecKey, decIv, AES_DECRYPT);

    /* Verify randomA */
    if (strncmp(randomA, decOut, RANDOM_STRING_LENGTH) != 0)
    {
    	printf("Random String Not Match\n");
    	exit(1);
    }

    /* get randomB */
    strncpy(randomB, decOut[RANDOM_STRING_LENGTH], RANDOM_STRING_LENGTH);

    /* generate initialization vector for AES encryption of randomB */
	RAND_bytes(encIv, AES_BLOCK_SIZE);
	/************************************
     * send encIv for randomB to server *
     ************************************/

    /********************************
     * wait for confirm message (?) *
     ********************************/

    /* AES encrypt with session key and sned randomB back to server */
    encOut = (unsigned char *) realloc(encOut, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE);
    AES_set_encrypt_key(sessionKey, AES_KEY_LENGTH, &aesEncKey);
    AES_cbc_encrypt(randomB, encOut, RANDOM_STRING_LENGTH, &aesEncKey, encIv, AES_ENCRYPT);
    /***********************************
     * send encOut (randomB) to server *
     ***********************************/

    RSA_free(keypair);
    BIO_free_all(pub);
    free(pubKey);
    free(encOut);
    free(decOut);
}
