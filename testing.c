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
#define RSA_PADDING RSA_PKCS1_OAEP_PADDING

void encryptWithAES(unsigned char* output, unsigned char* input, int inputLen, unsigned char* iv, unsigned char* key, int keyLen)
{
    AES_KEY aesKey;
    AES_set_encrypt_key(key, keyLen, &aesKey);
    AES_cbc_encrypt(input, output, inputLen, &aesKey, iv, AES_ENCRYPT);
}

void decryptWithAES(unsigned char* output, unsigned char* input, int inputLen, unsigned char* iv, unsigned char* key, int keyLen)
{
    AES_KEY aesKey;
    AES_set_decrypt_key(key, keyLen, &aesKey);
    AES_cbc_encrypt(input, output, inputLen, &aesKey, iv, AES_DECRYPT);
}

int extractRSAPubKey(unsigned char* pubKey, RSA* keypair)
{
    BIO* pub;
    int pubKeyLen;

    pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, keypair);
    pubKeyLen = BIO_pending(pub);
    // pubKey = (unsigned char *) malloc(pubKeyLen + 1);
    BIO_read(pub, pubKey, pubKeyLen);
    pubKey[pubKeyLen] = '\0';

    BIO_free_all(pub);
    return pubKeyLen;
}

int encryptWithRSAPubKey(unsigned char* output, unsigned char* input, int inputLen, unsigned char* pubKey)
{
    RSA* keypair;
    BIO* keybio;
    int cipherLen;

    keybio = BIO_new_mem_buf(pubKey, -1);
    keypair = PEM_read_bio_RSAPublicKey(keybio, &keypair,NULL, NULL);
    cipherLen = RSA_public_encrypt(inputLen, input, output, keypair, RSA_PADDING);

    RSA_free(keypair);
    BIO_free_all(keybio);
    return cipherLen;   /* return the size of ciphertext */
}

int decryptWithRSAPriKey(unsigned char* output, unsigned char* input, RSA* keypair)
{
    return RSA_private_decrypt(RSA_size(keypair), input, output, keypair, RSA_PADDING);
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
	AES_KEY aesKey, decKey;
	unsigned char *aesOut;
    unsigned char encIv[AES_BLOCK_SIZE];    /* initialization vector for AES encryption */
    unsigned char decIv[AES_BLOCK_SIZE];    /* initialization vector for AES decryption */
	RSA *keypair;	/* public/private key pair */
	BIO *pub;
	int pubKeyLen;
	unsigned char pubKey[RSA_KEY_LENGTH/8*2];
	unsigned char sessionKey[AES_KEY_LENGTH+1];
	unsigned char randomA[RANDOM_STRING_LENGTH+1];
	unsigned char randomB[RANDOM_STRING_LENGTH+1];
	unsigned char msg[512];	/* message from server */
	size_t msgLen;	/* length of message from server */
    unsigned char *decOut;

    RSA *keypair2 = NULL;   /* public/private key pair */
    BIO *keybio;
    int rsaEncLen;
    unsigned char *rsaOut;
    unsigned char sessionKey2[AES_KEY_LENGTH+1];
    unsigned char randomAnB[RANDOM_STRING_LENGTH*2+1];
    int sessionKey2Len;

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
	// getDigest(digest, salt, password);
    memcpy(digest, "rã-·∆CmÆ9∆/3V†&Æ$ÑõŒ∂\"8U“¶Ã", SHA256_DIGEST_LENGTH);

	/* generate public/private key pair for RSA */
	keypair = RSA_generate_key(RSA_KEY_LENGTH, RSA_KEY_EXP, NULL, NULL);

	/* extract public key from key pair */
	// pub = BIO_new(BIO_s_mem());
	// PEM_write_bio_RSAPublicKey(pub, keypair);
	// pubKeyLen = BIO_pending(pub);
 //    printf("pubKeyLen = %zu\n", pubKeyLen);
	// pubKey = (unsigned char *) malloc(pubKeyLen + 1);
 //    BIO_read(pub, pubKey, pubKeyLen);
	// pubKey[pubKeyLen] = '\0';

    printf("\n\nNow start testing AES for public Key\n\n");

    pubKeyLen = extractRSAPubKey(pubKey, keypair);
    printf("public key length = %d\n", pubKeyLen);
    printf("\n%s\n", pubKey);

	/* generate encIv for AES encryption of public key */
	RAND_bytes(encIv, AES_BLOCK_SIZE);
    strncpy(decIv, encIv, AES_BLOCK_SIZE);

    printf("-----start encrypting...-----\n");
	/* AES encrypt with digest and send public key to server */
    aesOut = (unsigned char *) malloc(RSA_KEY_LENGTH/8*2);
	// AES_set_encrypt_key(digest, SHA256_DIGEST_LENGTH*8, &aesKey);
 //    AES_cbc_encrypt(pubKey, aesOut, pubKeyLen, &aesKey, encIv, AES_ENCRYPT);
    encryptWithAES(aesOut, pubKey, pubKeyLen, encIv, digest, SHA256_DIGEST_LENGTH*8);
    printf("Encrypted pubKey length: %zu\n", strlen(aesOut));

    printf("-----start decrypting...-----\n");
    // memcpy(digest, "rã-·∆CmÆ9∆/3V†&Æ$ÑõŒ∂\"8U“¶Ã", SHA256_DIGEST_LENGTH);
    decOut = (unsigned char *) malloc(RSA_KEY_LENGTH/8*2);
    // AES_set_decrypt_key(digest, SHA256_DIGEST_LENGTH*8, &decKey);
    // AES_cbc_encrypt(aesOut, decOut, RSA_KEY_LENGTH/8*2, &decKey, decIv, AES_DECRYPT);
    decryptWithAES(decOut, aesOut, RSA_KEY_LENGTH/8*2, decIv, digest, SHA256_DIGEST_LENGTH*8);
    printf("\n%s\n", decOut);
    printf("Decrypted public key length: %zu\n", strlen(decOut));
    if (memcmp(decOut, "-----BEGIN RSA PUBLIC KEY-----", 30) == 0 && memcmp(decOut+strlen(decOut)-29, "-----END RSA PUBLIC KEY-----", 28) == 0)
        printf("public key valid\n");
    else
    {
        printf("public key invalid\n");
        exit(1);
    }

    if(memcmp(decOut, pubKey, pubKeyLen) == 0)
        printf("-----both public key match-----\n");
    else
    {
        printf("-----public key not match-----\n");
        exit(1);
    }





    printf("\n\nNow start testing RSA\n\n");

    /* generate session key */
    RAND_bytes(sessionKey, AES_KEY_LENGTH);
    sessionKey[AES_KEY_LENGTH] = '\0';
    printf("sessionKey = %s\n", sessionKey);
    printf("sessionKey length = %zu\n", strlen(sessionKey));

    /* RSA encrypt with public key and send session key to client */
    printf("-----start RSA encryption...-----\n");
    // keybio = BIO_new_mem_buf(decOut, -1);
    // keypair2 = PEM_read_bio_RSAPublicKey(keybio, &keypair2, NULL, NULL);
    // rsaOut = (unsigned char *) malloc(RSA_size(keypair2));
    // rsaEncLen = RSA_public_encrypt(AES_KEY_LENGTH, sessionKey, rsaOut, keypair2, RSA_PADDING);
    rsaOut = (unsigned char *) malloc(RSA_KEY_LENGTH/8);
    rsaEncLen = encryptWithRSAPubKey(rsaOut, sessionKey, AES_KEY_LENGTH, pubKey);
    printf("Encrypted session key length = %d\n", rsaEncLen);

    printf("-----start RSA decryption...-----\n");
    // msgLen = strlen(rsaOut);
    // printf("msgLen = %zu\n", msgLen);
    // sessionKey2Len = RSA_private_decrypt(RSA_size(keypair), rsaOut, sessionKey2, keypair, RSA_PADDING);
    sessionKey2Len = decryptWithRSAPriKey(sessionKey2, rsaOut, keypair);
    printf("Decrypted sessionKey length = %d\n", sessionKey2Len);
    sessionKey2[AES_KEY_LENGTH] = '\0';
    printf("Decrypted sessionKey = %s\n", sessionKey2);

    if (memcmp(sessionKey, sessionKey2, AES_KEY_LENGTH) == 0)
        printf("-----both session key matches-----\n");
    else
    {
        printf("-----session key not match-----\n");
        exit(1);
    }





    printf("\n\nNow start testing AES for randomA\n\n");

    /* generate randomA */
    RAND_bytes(randomA, RANDOM_STRING_LENGTH);
    randomA[RANDOM_STRING_LENGTH] = '\0';
    printf("randomA: %s\n", randomA);
    printf("randomA length = %zu\n", strlen(randomA));

    /* generate encIv for AES encryption of randomA */
    RAND_bytes(encIv, AES_BLOCK_SIZE);
    memcpy(decIv, encIv, AES_BLOCK_SIZE);

    printf("-----start encrypting...-----\n");
    /* AES encrypt with session key and send randomA to server */
    aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE);
    AES_set_encrypt_key(sessionKey, AES_KEY_LENGTH*8, &aesKey);
    AES_cbc_encrypt(randomA, aesOut, RANDOM_STRING_LENGTH, &aesKey, encIv, AES_ENCRYPT);
    printf("Ecrypted randomA length = %zu\n", strlen(aesOut));

    printf("-----start decrypting...-----\n");
    // decOut = (unsigned char *) realloc(decOut, RANDOM_STRING_LENGTH);
    AES_set_decrypt_key(sessionKey2, AES_KEY_LENGTH*8, &decKey);
    AES_cbc_encrypt(aesOut, randomB, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE, &decKey, decIv, AES_DECRYPT);
    randomB[RANDOM_STRING_LENGTH] = '\0';
    printf("Decrypted randomA length = %zu\n", strlen(randomB));
    printf("Dectypted randomA: %s\n", randomB);

    if (memcmp(randomA, randomB, AES_KEY_LENGTH) == 0)
        printf("-----both randomA matches-----\n");
    else
    {
        printf("-----randomA not match-----\n");
        exit(1);
    }





    printf("\n\nNow start testing AES for randomAnB\n\n");
    memcpy(randomAnB, randomA, RANDOM_STRING_LENGTH);
    memcpy(randomAnB+RANDOM_STRING_LENGTH, randomB, RANDOM_STRING_LENGTH);
    randomAnB[RANDOM_STRING_LENGTH*2] = '\0';
    printf("randomAnB: %s\n", randomAnB);
    printf("randomAnB length = %zu\n", strlen(randomAnB));

    printf("-----start encrypting...-----\n");
    /* generate encIv for AES encryption of randomAnB */
    RAND_bytes(encIv, AES_BLOCK_SIZE);
    memcpy(decIv, encIv, AES_BLOCK_SIZE);
    /* AES encrypt with session key and send randomA to server */
    aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE);
    AES_set_encrypt_key(sessionKey, AES_KEY_LENGTH*8, &aesKey);
    AES_cbc_encrypt(randomAnB, aesOut, RANDOM_STRING_LENGTH*2, &aesKey, encIv, AES_ENCRYPT);
    printf("Encrypted randomAnB length = %zu\n", strlen(aesOut));

    printf("-----start decrypting...-----\n");
    decOut = (unsigned char *) realloc(decOut, RANDOM_STRING_LENGTH*2+1);
    AES_set_decrypt_key(sessionKey2, AES_KEY_LENGTH*8, &decKey);
    AES_cbc_encrypt(aesOut, decOut, RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE, &decKey, decIv, AES_DECRYPT);
    decOut[RANDOM_STRING_LENGTH*2] = '\0';
    printf("Decrypted randomAnB length = %zu\n", strlen(randomAnB));
    printf("Decrypted randomAnB: %s\n", decOut);

    if (memcmp(randomAnB, decOut, RANDOM_STRING_LENGTH*2) == 0)
        printf("-----both randomAnB matches-----\n");
    else
    {
        printf("-----randomAnB not match-----\n");
        exit(1);
    }

    RSA_free(keypair);
    // BIO_free_all(pub);
    // free(pubKey);
    free(aesOut);
    free(decOut);
}
