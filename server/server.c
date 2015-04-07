#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h> 
#include <pthread.h>


#include "../linkedList.c"
#include "../server-login.c"

#define PORTNUMBER 7000
#define CREATE_USER "create_user.exe"	// change the name of the executable



int listenfd = 0;
struct sockaddr_in serv_addr; 


void* threadDo(void *arg);
int createUser(char*, char*);
void* one2oneChat_fromClient(void *arg);
void one2oneChat(struct OnlineUser*, struct OnlineUser*, int);

struct chatPair{
	struct OnlineUser *me;
	struct OnlineUser *receiver;
	int * connfd;
};

struct threadData{
	int* connfd;
};

int main(int argc, char *argv[])
{


    char sendBuff[1025];
    time_t ticks; 

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(sendBuff, '0', sizeof(sendBuff)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORTNUMBER); 

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 

    listen(listenfd, 10); 


	
    while(1)
    {	
		int connfd;

		connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 
		// one pthread for one connection
		
		struct threadData* arg = malloc(sizeof(struct threadData));
		arg->connfd = &connfd;
		pthread_t tid;
		int err = pthread_create(&tid, NULL, &threadDo, arg);
     }
}



void* threadDo(void *arg){
	unsigned long i = 0;
	pthread_t threadId = pthread_self();
	
	time_t ticks; 
	char sendBuff[1025];
	char recvBuff[1025];
	int n, connfd = 0, msgNumber = 0, authorized = 0;
	char userId[1024], password[1024];
	struct OnlineUser* me;
	
	struct threadData* arg_threadData = arg;
	connfd = *(arg_threadData->connfd);
	ticks = time(NULL);
	snprintf(sendBuff, sizeof(sendBuff), "%.24s - Connected\r\n", ctime(&ticks));
	write(connfd, sendBuff, strlen(sendBuff)); 
	while (1){
		n = read(connfd,recvBuff,sizeof(recvBuff));
		recvBuff[n] = 0;
		if (n>0)
		printf("%02x: Message Received (%d) - %s\n", (unsigned)threadId, msgNumber++, recvBuff);
		
		if (strcmp(recvBuff, "Command - login") == 0){
			// login
			puts("login");
			
			/*	login	*/
			
			unsigned char salt[SALT_LEN];
			unsigned char digest[SHA256_DIGEST_LENGTH];
			unsigned char *aesOut;	/* output of AES encryption / decryption */
			unsigned char encIv[AES_BLOCK_SIZE];    /* initialization vector for AES encryption */
			unsigned char decIv[AES_BLOCK_SIZE];    /* initialization vector for AES decryption */
			unsigned char *rsaOut;
			int rsaOutLen;
			unsigned char pubKey[RSA_KEY_LENGTH/8*2];
			unsigned char sessionKey[SESSION_KEY_LENGTH];
			unsigned char randomA[RANDOM_STRING_LENGTH];
			unsigned char randomB[RANDOM_STRING_LENGTH];
			unsigned char randomAnB[RANDOM_STRING_LENGTH*2];
			unsigned char msg[512];	/* message from server */

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

			/* read digest */
			readDigest(digest, /* inputFile */);

			/* decrypt the message and get public key */
			decryptWithAES(pubKey, msg, RSA_KEY_LENGTH/8*2, decIv, digest, SHA256_DIGEST_LENGTH);

			/* check if the decrypted data is in form of public key */
			if (memcmp(aesOut, "-----BEGIN RSA PUBLIC KEY-----", 30) == 0 && memcmp(aesOut+strlen(aesOut)-29, "-----END RSA PUBLIC KEY-----", 28) == 0)
			{
				printf("public key form valid\n");
				printf("correct password\n");
			}
			else
			{
				printf("public key invalid\n");
				printf("wrong password\n");
				exit(1);
			}

			/* generate session key */
			RAND_bytes(sessionKey, SESSION_KEY_LENGTH);

			/* RSA encrypt with public key and send session key to client */
			rsaOut = (unsigned char *) malloc(RSA_KEY_LENGTH/8);
			rsaOutLen = encryptWithRSAPubKey(rsaOut, sessionKey, SESSION_KEY_LENGTH, pubKey);

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
			decryptWithAES(randomA, msg, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE, decIv, sessionKey, SESSION_KEY_LENGTH);

			/* generate randomB */
			RAND_bytes(randomB, RANDOM_STRING_LENGTH);

			/* merge randomA and randomB */
			memcpy(randomAnB, randomA, RANDOM_STRING_LENGTH);
			memcpy(randomAnB+RANDOM_STRING_LENGTH, randomB, RANDOM_STRING_LENGTH);

			/* AES encrypt with session key and send randomAnB to client */
			aesOut = (unsigned char *) malloc(RANDOM_STRING_LENGTH*2+AES_BLOCK_SIZE);
			encryptWithAES(aesOut, randomAnB, RANDOM_STRING_LENGTH*2, encIv, sessionKey, SESSION_KEY_LENGTH);
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
			aesOut = (unsigned char *) realloc(aesOut, RANDOM_STRING_LENGTH);
			decryptWithAES(aesOut, msg, RANDOM_STRING_LENGTH+AES_BLOCK_SIZE, decIv, sessionKey, SESSION_KEY_LENGTH);

			/* Verify randomB */
			if (memcmp(randomB, aesOut, RANDOM_STRING_LENGTH) != 0)
			{
				printf("Invalid Random String!\n");
				exit(1);
			}

			free(aesOut);
			free(rsaOut);
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			/* Login end	*/
			
			
			
			
			// read userId
			n = read(connfd,recvBuff,sizeof(recvBuff));
			recvBuff[n] = 0;
			strcpy(userId, recvBuff);
			printf("user id = %s\n", userId);
			// reply
			strcpy(sendBuff, "OK");
			write(connfd, sendBuff, strlen(sendBuff)); 
			
			// read password
			n = read(connfd,recvBuff,sizeof(recvBuff));
			printf("n = %d\n", n);
			recvBuff[n] = 0;
			strcpy(password, recvBuff);
			
			
			printf("password = %s\n", password);
			me = insert(userId);
		} else if (strcmp(recvBuff, "Command - registration") == 0){
			// registration
			puts("registration");
			
			
			// read userId
			n = read(connfd,recvBuff,sizeof(recvBuff));
			recvBuff[n] = 0;
			strcpy(userId, recvBuff);
			
			// read password
			n = read(connfd,recvBuff,sizeof(recvBuff));
			recvBuff[n] = 0;
			strcpy(password, recvBuff);
			
			printf("user id = %s\n", userId);
			printf("password = %s\n", password);
			
			createUser(userId, password);
			
			
		} else if (strcmp(recvBuff, "Command - one2oneChat") == 0){
			// registration
			puts("one2oneChat");
			struct OnlineUser* receiver;
			// read userId
			n = read(connfd,recvBuff,sizeof(recvBuff)-1);
			recvBuff[n] = 0;
			char buff[1024];
			printf("%s\n", recvBuff);
			if (strcmp(recvBuff, "Command - sendRequest") == 0){
				n = read(connfd,recvBuff,sizeof(recvBuff)-1);
				recvBuff[n] = 0;
				receiver = find(recvBuff);
				if (receiver == NULL){
					// receiver does not exist
					puts("error-receiver is not online");
					snprintf(sendBuff, sizeof(sendBuff), "error-receiver is not online");
					write(connfd, sendBuff, strlen(sendBuff)); 
				} else{
					
					// receiver exist
					// write to receiver's pipe for notification
					write2Pipe(receiver, me->userId);
					readFromPipe(me, buff, sizeof(buff));
					printf("%s\n", buff);
					printf("I am %s: I am connecting with %s\n", me->userId, receiver->userId);
					readFromPipe(me, buff, sizeof(buff));
					printf("I am %s: 0\n", me->userId);
					
					snprintf(sendBuff, sizeof(sendBuff), "User %s is connecting with you\n", receiver->userId);
					write(connfd, sendBuff, strlen(sendBuff)); 
					
					/* Start chatting	*/
					pthread_t tid1;
					struct chatPair *args = malloc(sizeof(*args));
					args->me = me;
					args->receiver = receiver;
					args->connfd = &connfd;
					

					int err = pthread_create(&tid1, NULL, &one2oneChat_fromClient, args);
					if (err != 0 ){
						puts("Error in creating thread\n");
					}
					one2oneChat(me, receiver, connfd);
				}
			} else if (strcmp(recvBuff, "Command - waitRequest") == 0){
				readFromPipe(me, buff, sizeof(buff));
				receiver = find(buff);
				if (receiver == NULL){
					// receiver does not exist
					puts("error-receiver is not online");
				}else{
					write2Pipe(receiver, "OK");
					printf("I am %s: I am connecting with %s\n", me->userId, receiver->userId);
					snprintf(sendBuff, sizeof(sendBuff), "User %s is asking for set up a connection with you\n", receiver->userId);
					write(connfd, sendBuff, strlen(sendBuff)); 
					
					n = read(connfd,recvBuff,sizeof(recvBuff)-1);
					recvBuff[n] = 0;
					puts("0");
					if (strcmp(recvBuff, "OK") == 0){
						/* Start chatting	*/
						write2Pipe(receiver, "OK");
						pthread_t tid1;
						
						printf("I am %s: 0\n", me->userId);
						struct chatPair *args = malloc(sizeof(struct chatPair ));
						args->me = me;
						args->receiver = receiver;
						args->connfd = &connfd;
printf("I am %s: 01\n", me->userId);
						int err = pthread_create(&tid1, NULL, &one2oneChat_fromClient, args);
						if (err != 0 ){
							puts("Error in creating thread");
							printf("%d\n", err);
						}
						one2oneChat(me, receiver, connfd);
					}
				}
			}
			
			// check if the receiver exist

			
		} else if (strcmp(recvBuff, "Command - n2nChat") == 0){
			// registration
			puts("one2oneChat");
			char receiver[50];
			
			// read userId
			n = read(connfd,recvBuff,sizeof(recvBuff));
			recvBuff[n] = 0;
			
			// dangerous
			strcpy(receiver, recvBuff);
			
			
			
		}
	
		/*
		while ((n = read(connfd,recvBuff,sizeof(recvBuff))) > 0){
			printf("%d\n", n);
			recvBuff[n] = 0;
			printf("Message Received (%d) - %s\n", msgNumber++, recvBuff);
		}
		*/
		sleep(1);
	}
	close(connfd);
	sleep(1);
	
	return NULL;
}

int createUser(char* userId, char* password){
	int childPid = fork();
	if (childPid < 0){
		puts("ERROR!!");
		puts("Fork failed");
		puts("create_user will be terminated");
	} else if (childPid == 0){	// child
		execlp("./create_user", "./create_user", userId, password, (char*) NULL);
	
		exit(0);
	} 
	wait(NULL);
}

void one2oneChat(struct OnlineUser* me, struct OnlineUser* receiver, int connfd){
	char sendBuff[1024], recvBuff[1024];
	while(1){
		readFromPipe(me, recvBuff, sizeof(sendBuff));
		if (strlen(recvBuff) > 0){
			sprintf(sendBuff, "*New Message From %s: ", me->userId);
			strcat(sendBuff, recvBuff);
			printf("%s\n", sendBuff);
			write(connfd, sendBuff, strlen(sendBuff)); 
		}
	}
}

void* one2oneChat_fromClient(void *arg){
	puts("test");
	int n;
	char recvBuff[1024];
	
	struct chatPair* myPaire = (struct chatPair*)arg;
	
	
	
	struct OnlineUser* me = myPaire->me;
	struct OnlineUser* receiver = myPaire->receiver;
	int *connfd = myPaire->connfd;
	printf("I am %s: 2\n", me->userId);
	printf("%s %s %d\n", me->userId, receiver->userId, *connfd);
	while(1){
		n = read(*connfd,recvBuff,sizeof(recvBuff));
		if ( n > 0){
			recvBuff[n] = 0;
			printf("%s\n", recvBuff);
			write2Pipe(receiver, recvBuff);
		}
	}
	pthread_exit(0);
}
