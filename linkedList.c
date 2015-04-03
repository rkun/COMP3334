struct OnlineUser{
	char userId[50];
	struct OnlineUser *next;
	struct OnlineUser *previous;
};

struct OnlineUser *head, *tail;

void insert(char userId[]){
	struct OnlineUser *newNode;
	newNode = (struct OnlineUser *) malloc(sizeof(struct OnlineUser));
	strcpy(newNode->userId, userId);
	newNode->next = NULL;
	
	if (head == NULL){
		head = newNode;
	}
	
	tail->next = newNode;
	newNode->previous = tail;
	tail = newNode;
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
	while (head != NULL){
		if (strcmp(userId, cur->userId) == 0)
			return cur;
		cur = cur->next;
	}
	return NULL;
}
