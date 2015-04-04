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
	char userId[50], password[50];
	scanf("%s %s", &userId, &password);

	sendMsg(userId);
	printf("user id = %s\n", userId);
	recieveMsg();
			
			printf("password = %s\n", password);
	sendMsg(password);
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