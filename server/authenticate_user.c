#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#define SALT_LEN 32
#define IPAD 0x36
#define OPAD 0x5C
#define SHA256_BLOCK_LENGTH 64

void readSalt();
void readDigest();
void readHMAC();
void getHMAC();
void getDigest();
void authenUser();

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

void readHMAC(unsigned char* hmac, FILE* inputFile)
{
	fgetc(inputFile);
	fread(hmac, SHA256_DIGEST_LENGTH, 1, inputFile);
}

void getHMAC(unsigned char* hmac, unsigned char* digest)
{
	/* the secret key is generated from http://randomkeygen.com */
	unsigned char secret[] = "YG2qRhUav98h0y0i6Q6hpSP5Kkk1Xb1VZGSVbR3c5W32yb76I2h4Nb2mSK4CwgZ2";
	unsigned char ipad[SHA256_BLOCK_LENGTH];
	unsigned char opad[SHA256_BLOCK_LENGTH];
	unsigned char xorResult[SHA256_BLOCK_LENGTH];
	unsigned char combination[SHA256_BLOCK_LENGTH + SHA256_DIGEST_LENGTH];
	int i;

	/* generate ipad and opad */
	for (i = 0; i < SHA256_BLOCK_LENGTH; i++)
	{
		ipad[i] = IPAD;
		opad[i] = OPAD;
	}

	/* secret key XOR ipad */
	for (i = 0; i < SHA256_BLOCK_LENGTH; i++)
		xorResult[i] = secret[i] ^ ipad[i];

	/* combine and hash XOR Result and Salted-hashed Password */
	memcpy(combination, xorResult, SHA256_BLOCK_LENGTH);
	memcpy(combination + SHA256_BLOCK_LENGTH, digest, SHA256_DIGEST_LENGTH);
	SHA256(combination, SHA256_BLOCK_LENGTH + SHA256_DIGEST_LENGTH, hmac);

	/* secret key XOR opad */
	for (i = 0; i < SHA256_BLOCK_LENGTH; i++)
		xorResult[i] = secret[i] ^ opad[i];

	/* combine and hash XOR Result and the hash result above */
	memcpy(combination, xorResult, SHA256_BLOCK_LENGTH);
	memcpy(combination + SHA256_BLOCK_LENGTH, hmac, SHA256_DIGEST_LENGTH);
	SHA256(combination, SHA256_BLOCK_LENGTH + SHA256_DIGEST_LENGTH, hmac);
}

void getDigest(unsigned char* digest, unsigned char* salt, char* password)
{
	int pwlength = strlen(password);
	int totalLength = SALT_LEN + pwlength;
	unsigned char pwAndSalt[totalLength];
	memcpy(pwAndSalt, password, pwlength);
	memcpy(pwAndSalt + pwlength, salt, SALT_LEN);
	SHA256((unsigned char*)pwAndSalt, totalLength, digest);
}

void authenUser(char* username, char* password, FILE* inputFile)
{
	unsigned char salt[SALT_LEN];
	unsigned char oldDigest[SHA256_DIGEST_LENGTH];
	unsigned char newDigest[SHA256_DIGEST_LENGTH];
	unsigned char oldHmac[SHA256_DIGEST_LENGTH];
	unsigned char newHmac[SHA256_DIGEST_LENGTH];
	ssize_t nByte;

	readSalt(salt, username, inputFile);
	readDigest(oldDigest, inputFile);
	readHMAC(oldHmac, inputFile);

	/*
	 * compare the HMAC generated in this program and the one in users.txt
	 * if they match, salted-hashed password stored in users.txt is not modified by third party
	 * if not, reject the authenticatation
	 */
	getHMAC(newHmac, oldDigest);
	if (memcmp(oldHmac, newHmac, SHA256_DIGEST_LENGTH) != 0)
	{
		printf("Your account is illegally modified by someone, please contact administrator.\n");
		return;
	}

	/* compare the digest generated in this program and the salted-hashed password stored in users.txt to authenticate users */
	getDigest(newDigest, salt, password);
	if (memcmp(oldDigest, newDigest, SHA256_DIGEST_LENGTH) == 0)
		printf("You are an authenticated user.\n");
	else
		printf("Wrong Password\n");
}

int main(int argc, char *argv[])
{
    FILE* inputFile = fopen("users.txt", "r");
    char input[21];
    char username[21];
    char password[21];
    int counter = 0;	/* to judge whether handling username or password */

	strcpy(username, argv[1])
	strcpy(password, argv[2]);
	authenUser(username, password, inputFile);
	
    fclose(inputFile);
}