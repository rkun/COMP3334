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
#include <string.h>

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


int main(int argc, char *argv[])
{
	connect2Server();
	welcome();
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
	while ((n = read(sockfd,recvBuff,sizeof(recvBuff))) > 0){
		recvBuff[n] = 0;
		printf("%s", recvBuff);
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
		scnaf(" %d", &command);
		switch(command){
			case 1:
				one2oneChat();
				break;
			case 2:
				n2nChat();
				break;
		}
	}
}

void one2oneChat(){
	char receiver[50];
	printf("*Please enter the userId of the other user");
	scanf(" %s", receiver);
	
	sendMsg("Command - one2oneChat");
	sendMsg(receiver);
}


void n2nChat(){

}