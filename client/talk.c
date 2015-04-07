#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <pthread.h>
#include "../client-login.c"


#define PORTNUMBER 7000
#define HOSTNAME "127.0.0.1"

int sockfd = 0, n = 0;
char recvBuff[1025];
char sendBuff[1024];
struct sockaddr_in serv_addr;

int connect2Server();
void sendMsg(char* msg);
void recieveMsg();
int getPass(char*, int);	// not working now, fix later. get the password without displaying the password in stdout when the user input the password
void welcome();
void login();
void registration();
void chooseChat();
void one2oneChat();
void n2nChat();
void one2oneChat_waitRequest();
void one2oneChat_sendRequest();
void one2oneChat_chat();
void* one2oneChat_chat_r(void *);
void one2oneChat_chat_s();

int main(int argc, char *argv[])
{
	connect2Server();
	welcome();
	chooseChat();
	chooseChat();

    return 0;
}

int connect2Server(){
    memset(recvBuff, '0',sizeof(recvBuff));
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORTNUMBER); 
	
    if(inet_pton(AF_INET, HOSTNAME, &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    } 
    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return 1;
    }
    while ( (n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0)
    {
        recvBuff[n] = 0;
        if(fputs(recvBuff, stdout) == EOF)
        {
            printf("\n Error : Fputs error\n");
        } else{
			break;
		}
    } 
    if(n < 0)
    {
        printf("\n Read error \n");
    } 
	return 0;
}

void sendMsg(char* msg){
	int msgNumber = 0;
	while (strlen(msg) > 1024){
		//printf("strlen(msg) = %d\n", strlen(msg));
		strncpy(sendBuff, msg, sizeof(sendBuff));
		//printf("Sending Message (%d) - %s\n", msgNumber++, sendBuff);
		if (write(sockfd,sendBuff,sizeof(sendBuff)) < 0)
			printf("error in writing on stream socket\n");
		msg += 1024;
		sleep(1);
	}
	//printf("strlen(msg) = %d\n", strlen(msg));
	strncpy(sendBuff, msg, sizeof(sendBuff));
//	printf("Sending Message (%d) - %s\n", msgNumber++, sendBuff);
	if (write(sockfd,sendBuff,sizeof(sendBuff)) < 0)
		printf("error in writing on stream socket\n");
}

void recieveMsg(){
	
	while ((n = read(sockfd,recvBuff,sizeof(recvBuff) - 1)) > 0){
		recvBuff[n] = 0;
        if(fputs(recvBuff, stdout) == EOF)
        {
            printf("\n Error : Fputs error\n");
        } else{
			break;
		}
	}
	
}

// not working now, fix later. 
int getPass(char* password, int size){
	char c;
	int n = 0;
	do {
		c = getchar();
		if (c != '\n' || c != '\r'){
			password[n++] = c;
		}
		else
			break;
	} while ( n < (size - 1) );
	password[n] = 0;
	return n;
}

void welcome(){
	char c;
	printf("**********************************************************************\n");
	printf("*************************Welcome To Talk******************************\n");
	printf("Are you an existing user? (Y/N)\n");
	
	int pass = 0;
	while (pass == 0){
		printf("> ");
		scanf(" %c", &c);
		switch (c){
			case 'Y':
			case 'y':
				login();
				pass = 1;
				break;
			case 'N':
			case 'n':
				registration();
				pass = 1;
				break;
		}
	}
}

void login(){
	sendMsg("Command - login");
	char userId[50], password[50], salt[1024];

	
	/*	Login	*/
	unsigned char salt[SALT_LEN];
	unsigned char digest[SHA256_DIGEST_LENGTH];
<<<<<<< HEAD
	AES_KEY aesKey;
	unsigned char *aesOut;
	unsigned char iv[AES_BLOCK_SIZE];	/* initialization vector for AES */
	RSA *keypair;	/* public/private key pair */
	BIO *pub;
	size_t pubLen;
	unsigned char *pubKey;
	unsigned char sessionKey[AES_KEY_LENGTH];
	unsigned char randomA[AES_KEY_LENGTH];
	unsigned char randomB[AES_KEY_LENGTH];
	unsigned char msg[512];	/* message from server */
	size_t msgLen;	/* length of message from server */
=======
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
>>>>>>> 8e035cf0d1f668cd03a97d19f0103fae22b67b41

	/****************************************
	 * read username and password from user *
	 ****************************************/
	printf("Enter the username\n> ");
	scanf(" %s", &userId);
	printf("Enter the password\n> ");
	scanf(" %s", &password);
	
	/***************************
	 * send username to server *
	 ***************************/
	sendMsg(userId);
	
	/****************************
	 * receive salt from server *
	 ****************************/
	n = read(sockfd,recvBuff,sizeof(recvBuff) - 1;
	recvBuff[n] = 0;
	strcpy(salt, recvBuff);
	
	/* generate hash of password+salt */
<<<<<<< HEAD
	getDigest(digest, salt, password);
=======
	getDigest(digest, salt, /* password */);
>>>>>>> 8e035cf0d1f668cd03a97d19f0103fae22b67b41

	/* generate public/private key pair for RSA */
	keypair = RSA_generate_key(RSA_KEY_LENGTH, RSA_KEY_EXP, NULL, NULL);

	/* extract public key from key pair */
<<<<<<< HEAD
	pub = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(pub, keypair);
	pubLen = BIO_pending(pub);
	pubKey = malloc(pubLen + 1);
	pubKey[pubLen] = '\0';

	/* generate initialization vector for AES encryption of public key */
	RAND_bytes(iv, AES_BLOCK_SIZE);
	/***********************************
	 * send iv for pubKey to server *
	 ***********************************/
	sendMsg(iv);
	 
	/********************************
	 * wait for confirm message (?) *
	 ********************************/
	recieveMsg();
	 
	/* AES encrypt with digest and send public key to server */
	aesOut = (unsigned char *) malloc(pubLen+AES_BLOCK_SIZE);
	AES_set_encrypt_key(digest, SHA256_DIGEST_LENGTH, &aesKey);
	AES_cbc_encrypt(pubKey, aesOut, pubLen, &aesKey, iv, AES_ENCRYPT);
=======
	pubKeyLen = extractRSAPubKey(pubKey, keypair);


	/* generate encIv for AES encryption of public key */
	RAND_bytes(encIv, AES_BLOCK_SIZE);
	/***********************************
	 * send encIv for pubKey to server *
	 ***********************************/
	 sendMsg(encIv);
	 

	/*************************************
	 * wait for confirmation message (?) *
	 *************************************/
	recieveMsg();
	 
	/* AES encrypt with digest and send public key to server */
	aesOut = (unsigned char *) malloc(RSA_KEY_LENGTH/8*2);
	encryptWithAES(aesOut, pubKey, pubKeyLen, encIv, digest, SHA256_DIGEST_LENGTH);
>>>>>>> 8e035cf0d1f668cd03a97d19f0103fae22b67b41
	/**********************************
	 * send aesOut (pubKey) to server *
	 **********************************/
	sendMsg(aesOut(pubKey));
<<<<<<< HEAD
	/********************************************
	 * receive message (sessionKey) from server *
	 ********************************************/
	n = read(sockfd,msg,sizeof(msg));
	msg[n] = 0;
	 
	/* decrypt the message and get session key */
	msgLen = strlen(msg);
	RSA_private_decrypt(msgLen, msg, sessionKey, keypair, RSA_PKCS1_OAEP_PADDING);

	/* generate a random string */
	RAND_bytes(randomA, RANDOM_STRING_LENGTH);

	/* generate initialization vector for AES encryption of randomA */
	RAND_bytes(iv, AES_BLOCK_SIZE);
	/************************************
	 * send iv for randomA to server *
	 ************************************/
	sendMsg(iv);

	 
	/*************************************************
	 * receive iv for randomA+randomB from server *
	 *************************************************/
	n = read(sockfd,iv,sizeof(iv));
	iv[n] = 0;
	
	
	/* AES encrypt with session key and send the random string to server */
	aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE);
	AES_set_encrypt_key(sessionKey, AES_KEY_LENGTH, &aesKey);
	AES_cbc_encrypt(randomA, aesOut, RANDOM_STRING_LENGTH, &aesKey, iv, AES_ENCRYPT);
=======
	/*********************************************
	 * receive encrypted session key from server *
	 *********************************************/
	 *************************************************/
	n = read(sockfd,sessionKey,sizeof(sessionKey));
	sessionKey[n] = 0;
	 
	/* decrypt the message and get session key */
	sesKeyLen = decryptWithRSAPriKey(sessionKey, msg, keypair);

	/* generate randomA */
	RAND_bytes(randomA, RANDOM_STRING_LENGTH);

	/* generate encIv for AES encryption of randomA */
	RAND_bytes(encIv, AES_BLOCK_SIZE);

	/************************************
	 * send encIv for randomA to server *
	 ************************************/
	sendMsg(encIv);
	/*************************************************
	 * receive decIv for randomA+randomB from server *
	 *************************************************/
	n = read(sockfd,sessionKey,sizeof(sessionKey));
	sessionKey[n] = 0;
	 
	 
	/* AES encrypt with session key and send randomA to server */
	aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE);
	encryptWithAES(aesOut, randomA, RANDOM_STRING_LENGTH, encIv, sessionKey, sesKeyLen);

>>>>>>> 8e035cf0d1f668cd03a97d19f0103fae22b67b41
	/***********************************
	 * send aesOut (randomA) to server *
	 ***********************************/

	/*************************************************
<<<<<<< HEAD
	 * receive message (randomA+randomB) from server *
	 *************************************************/
	/* decrypt the message and get random string A and B */
	aesOut = (unsigned char *) malloc(RANDOM_STRING_LENGTH*2);
	AES_set_decrypt_key(sessionKey, AES_KEY_LENGTH, &aesKey);
	AES_cbc_encrypt(msg, aesOut, RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE, &aesKey, iv, AES_DECRYPT);

	/* Verify randomA */
	if (strncmp(randomA, aesOut, RANDOM_STRING_LENGTH) != 0)
	{
		printf("Random String Not Match\n");
=======
	 * receive encrypted randomA+randomB from server *
	 *************************************************/
	/* decrypt the message and get random string A and B */
	aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH*2);
	decryptWithAES(aesOut, msg, RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE, decIv, sessionKey, sesKeyLen);

	/* Verify randomA */
	if (memcmp(randomA, aesOut, RANDOM_STRING_LENGTH) != 0)
	{
		printf("Invalid Random String!\n");
>>>>>>> 8e035cf0d1f668cd03a97d19f0103fae22b67b41
		exit(1);
	}

	/* get randomB */
<<<<<<< HEAD
	strncpy(randomB, aesOut[RANDOM_STRING_LENGTH], RANDOM_STRING_LENGTH);

	/* generate initialization vector for AES encryption of randomB */
	RAND_bytes(iv, AES_BLOCK_SIZE);
	/************************************
	 * send iv for randomB to server *
	 ************************************/

	/********************************
	 * wait for confirm message (?) *
	 ********************************/

	/* AES encrypt with session key and sned randomB back to server */
	aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE);
	AES_set_encrypt_key(sessionKey, AES_KEY_LENGTH, &aesKey);
	AES_cbc_encrypt(randomB, aesOut, RANDOM_STRING_LENGTH, &aesKey, iv, AES_ENCRYPT);
=======
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
>>>>>>> 8e035cf0d1f668cd03a97d19f0103fae22b67b41
	/***********************************
	 * send aesOut (randomB) to server *
	 ***********************************/

	RSA_free(keypair);
<<<<<<< HEAD
	BIO_free_all(pub);
	free(pubKey);
=======
>>>>>>> 8e035cf0d1f668cd03a97d19f0103fae22b67b41
	free(aesOut);
	/*
	recieveMsg();
			
	printf("password = %s\n", password);
	sendMsg(password);
	*/
}

void registration(){
	// send command to server
	sendMsg("Command - registration");
	
	// get input from user
	char userId[50], password[50];
	printf("New User Id > ");
	scanf(" %s", &userId);
	printf("Password > ");
	scanf(" %s", &password);
	
	// send userID and Password to server
	sendMsg(userId);
	sendMsg(password);
	
	// get response
	recieveMsg();
	
	
}

void chooseChat(){
	printf("\n");
	printf("**********************************************************************\n");
	printf("*Please choose the chat mode you want to enter\n");
	printf("* 1. 1-1 Chat\n");
	printf("* 2. n-n Chat\n");
	
	int command, pass = 0;
	while (pass == 0){
		printf("> ");
		scanf(" %d", &command);
		switch(command){
			case 1:
				one2oneChat();
				pass = 1;
				break;
			case 2:
				n2nChat();
				pass = 1;
				break;
		}
	}
}

void one2oneChat(){
	sendMsg("Command - one2oneChat");
	printf("**********************************************************************\n");
	printf("* 1. Wait for request\n");
	printf("* 2. Send request to other user\n");
	
	int command, pass = 0;
	while (pass == 0){
		printf("> ");
		scanf(" %d", &command);
		switch(command){
			case 1:
				one2oneChat_waitRequest();
				pass = 1;
				break;
			case 2:
				one2oneChat_sendRequest();
				pass = 1;
				break;
		}
	}

}


void one2oneChat_waitRequest(){
	char receiver[50];
	sendMsg("Command - waitRequest");
	printf("Waiting for request....\n");
	recieveMsg();
	printf("Accept? (Y/N)\n");
	char c;
	int pass = 0;
	while (pass == 0){
		printf("> ");
		scanf(" %c", &c);
		switch (c){
			case 'Y':
			case 'y':
				sendMsg("OK");
				printf("Start\n");
				one2oneChat_chat();
				pass = 1;
				break;
			case 'N':
			case 'n':

				pass = 1;
				break;
		}
	}
	
	
}

void one2oneChat_sendRequest(){
	char receiver[50];
	sendMsg("Command - sendRequest");
	
	printf("*Please enter the userId of the other user\n> ");
	scanf(" %s", &receiver);
	sendMsg(receiver);
	printf("Waiting\n");
	recieveMsg();
	one2oneChat_chat();
}

void one2oneChat_chat(){
	pthread_t tid;
	int err = pthread_create(&tid, NULL, &one2oneChat_chat_r, NULL);
	one2oneChat_chat_s();
}

void* one2oneChat_chat_r(void* arg){
	//puts("Receiving");
	while(1){
		recieveMsg();
		printf("\n> ");
		fflush(stdout);
	}
}
void one2oneChat_chat_s(){
	//puts("Sending");
	char msg[1024];
	getchar();
	while(1){
		printf("> ");
		gets(msg);
		printf("> You send: %s\n", msg);
		sendMsg(msg);
	}
}


void n2nChat(){

}