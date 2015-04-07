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
#define SESSION_KEY_LENGTH 32
#define RANDOM_STRING_LENGTH 32
#define RSA_KEY_LENGTH 2048	/* bit */
#define RSA_KEY_EXP 3
#define RSA_PADDING RSA_PKCS1_OAEP_PADDING

void encryptWithAES(unsigned char* output, unsigned char* input, int inputLen, unsigned char* iv, unsigned char* key, int keyLen)
{	/* inputLen and keyLen are in bytes */
    AES_KEY aesKey;
    AES_set_encrypt_key(key, keyLen*8, &aesKey);
    AES_cbc_encrypt(input, output, inputLen, &aesKey, iv, AES_ENCRYPT);
}

void decryptWithAES(unsigned char* output, unsigned char* input, int inputLen, unsigned char* iv, unsigned char* key, int keyLen)
{	/* inputLen and keyLen are in bytes */
    AES_KEY aesKey;
    AES_set_decrypt_key(key, keyLen*8, &aesKey);
    AES_cbc_encrypt(input, output, inputLen, &aesKey, iv, AES_DECRYPT);
}

int encryptWithRSAPubKey(unsigned char* output, unsigned char* input, int inputLen, unsigned char* pubKey)
{	/* inputLen is in bytes */
    RSA* keypair;
    BIO* keybio;
    int cipherLen;

    keybio = BIO_new_mem_buf(pubKey, -1);
    keypair = PEM_read_bio_RSAPublicKey(keybio, &keypair,NULL, NULL);
    cipherLen = RSA_public_encrypt(inputLen, input, output, keypair, RSA_PADDING);

    RSA_free(keypair);
    BIO_free_all(keybio);
    return cipherLen;	/* return the size of ciphertext */
}

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
