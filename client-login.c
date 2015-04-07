/*
	1. Alice generates public/private key pair unique for the session Pa (private) and P'a (public) Alice encrypts public key using S and sends it to Bob.

	2. Bob (knowing S) decrypts Alices message and recovers Alice's public key P'a. Bob generates random session key K. Bob encrypts K with Alice's public key P'a and sends it to Alice.

	3. Alice decrypts the message and obtains K. Alice generates random string Ra, encrypts it with K and sends to bob

	4. Bob decrypts the message to obtain Ra, generates another random Rb, encrypts both with K and sends the encrypted message to Alice.

	5. Alice decrypts message, verifies her own Ra being valid in the message. She encrypts only Rb with K and sends to Bob.

	6. Bob decrypts Rb and verifies his own Rb being valid.
*/

<<<<<<< HEAD
=======
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
>>>>>>> 8e035cf0d1f668cd03a97d19f0103fae22b67b41
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define SALT_LEN 32
<<<<<<< HEAD
#define SHA256_BLOCK_LENGTH 64
#define AES_KEY_LENGTH 32
#define RANDOM_STRING_LENGTH 32
#define RSA_KEY_LENGTH 2048	/* bit */
#define RSA_KEY_EXP 3
=======
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
>>>>>>> 8e035cf0d1f668cd03a97d19f0103fae22b67b41

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
