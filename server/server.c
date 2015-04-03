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

#define PORTNUMBER 7000
#define CREATE_USER "create_user.exe"	// change the name of the executable

int listenfd = 0;
struct sockaddr_in serv_addr; 


void* threadDo(void *arg);
int createUser(char*, char*);
char onlineUser[1000][100];

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
		// one pthread for one connection
		pthread_t tid;
		int err = pthread_create(&tid, NULL, &threadDo, NULL);
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
	
	connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 
	ticks = time(NULL);
	snprintf(sendBuff, sizeof(sendBuff), "%.24s - Connected\r\n", ctime(&ticks));
	write(connfd, sendBuff, strlen(sendBuff)); 
	while (1){
		n = read(connfd,recvBuff,sizeof(recvBuff));
		recvBuff[n] = 0;
		printf("%02x: Message Received (%d) - %s\n", (unsigned)threadId, msgNumber++, recvBuff);
		
		if (strcmp(recvBuff, "Command - login") == 0){
			// login
			puts("login");
			
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
			char receiver[50]
			
			// read userId
			n = read(connfd,recvBuff,sizeof(recvBuff));
			recvBuff[n] = 0;
			
			// dangerous
			strcpy(receiver, recvBuff);
			// check if the receiver exist
			struct OnlineUser = find(receiver);
			if (receiver == NULL){
				// receiver does not exist
				snprintf(sendBuff, sizeof(sendBuff), "error-receiver is not online");
				write(connfd, sendBuff, strlen(sendBuff)); 
			} else{
			
			
			}
			
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