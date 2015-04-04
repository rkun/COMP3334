struct OnlineUser{
	char userId[50];
	int fd[2];
	struct OnlineUser *next;
	struct OnlineUser *previous;
};

struct OnlineUser *head = NULL, *tail = NULL;


struct OnlineUser* insert(char userId[]){
	struct OnlineUser *newNode;
	newNode = (struct OnlineUser *) malloc(sizeof(struct OnlineUser));
	strcpy(newNode->userId, userId);
	newNode->next = NULL;
	pipe(newNode->fd);
	
	if (head == NULL){
		head = newNode;
	}

	if (tail != NULL){
		tail->next = newNode;
		newNode->previous = tail;
	}
	tail = newNode;
	return newNode;
}

int delete(struct OnlineUser *user){
	(user->previous)->next = user->next;
	(user->next)->previous = user->previous;
	if (head == user){
		head = user->next;
	}
	if (tail == user){
		tail = user->previous;
	}
	free(user);
	return 0;
}

struct OnlineUser* find(char userId[]){
	struct OnlineUser *cur = head;
	while (cur != NULL){
		if (strcmp(userId, cur->userId) == 0)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

void write2Pipe(struct OnlineUser *user, char* msg){
	char sendBuff[1024];
	int msgNumber = 0;
	
	while (strlen(msg) > 1024){

		strncpy(sendBuff, msg, sizeof(sendBuff));

		if (write(user->fd[1],sendBuff,sizeof(sendBuff)) < 0)
			printf("error in writing on stream socket\n");
		msg += 1024;
		sleep(1);
	}

	strncpy(sendBuff, msg, sizeof(sendBuff));
	if (write(user->fd[1],sendBuff,sizeof(sendBuff)) < 0)
		printf("error in writing on stream socket\n");
}

void readFromPipe(struct OnlineUser *user, char* msg, int size){
	int n = 0;
	n = read(user->fd[0],msg, size);
	msg[n] = 0;
	printf("%s\n", msg);
	/*
	while ((n = read(user->fd[0],msg, size)) > 0){
        if(fputs(msg, stdout) == EOF)
        {
            printf("\n Error : Fputs error\n");
        } else{
			break;
		}
	}
	*/
}