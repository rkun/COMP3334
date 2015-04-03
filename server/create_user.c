#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
/* testbranch */
#define SALT_LEN 32
#define IPAD 0x36
#define OPAD 0x5C
#define SHA256_BLOCK_LENGTH 64
/* hellorenee */
void getSalt();
void getDigest();
void getHMAC();
void createUser();

void getSalt(unsigned char* salt, int randomDataFd)
{
	ssize_t nByte;
	nByte = read(randomDataFd, salt, SALT_LEN);
	if (nByte < 0)
	{
		printf("Error: Unable to read /dev/random\n");
		exit(1);
	}
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

void createUser(char* username, char* password, int randomDataFd, int outputFd)
{
	unsigned char salt[SALT_LEN];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned char hmac[SHA256_DIGEST_LENGTH];
	ssize_t nByte;

	getSalt(salt, randomDataFd);
	getDigest(digest, salt, password);
	getHMAC(hmac, digest);

	nByte = write(outputFd, username, strlen(username));
	nByte = write(outputFd, "|", 1);
	nByte = write(outputFd, salt, SALT_LEN);
	nByte = write(outputFd, "|", 1);
	nByte = write(outputFd, digest, SHA256_DIGEST_LENGTH);
	nByte = write(outputFd, "|", 1);
	nByte = write(outputFd, hmac, SHA256_DIGEST_LENGTH);
	nByte = write(outputFd, "\n", 1);

	printf("User %s is created!\n", username);
	printf("---------------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
    int randomDataFd = open("/dev/urandom", O_RDONLY);
    int outputFd = open("users.txt", O_CREAT | O_WRONLY | O_APPEND, 0644);
    char input[21];
    char username[21];
    char password[21];
    int counter = 0;	/* to judge whether handling username or password */

	
	strcpy(username, argv[1]);
	strcpy(password, argv[2]);
	createUser(username, password, randomDataFd, outputFd);
	
    close(randomDataFd);
    close(outputFd);
}