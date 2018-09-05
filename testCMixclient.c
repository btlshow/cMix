#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include "miracl.h"
#include "mirdef.h"
#include <time.h>

#define MSGNUM 5 
#define CIPHERSIZE 40920
#define MSGSIZE 4092
#define SOCKNUM 3 
#define PORT_SERVER 38080
#define OVERTIME 300
#define DEC 10

void getServerPort(int *server_Port);
int getServerSocket(int *server_Socket,struct sockaddr_in *server_Sockaddr,int server_Port[SOCKNUM]);
int connectCMix(int server_Socket[SOCKNUM],struct sockaddr_in server_Sockaddr[SOCKNUM]);
int getpublicShareKey(int server_Socket,char *publicShareKey_KStr);
void encryptoMessage(char publicShareKey_KStr[SOCKNUM][CIPHERSIZE],char *cryptoMessage);
int sendAndRecvMessage(int serverSocket,char cryptoMessage[CIPHERSIZE]);
int recvMsg(int prior_Socket,char* prior_Msg);
int recvpriorMsg(int prior_Socket,char (*prior_Msg)[CIPHERSIZE]);
int sendMsg(int next_Socket,char* next_Msg);
int sendnextMsg(int next_Socket,char (*next_Msg)[CIPHERSIZE]);
int cutStr(char *origStr,char *cutStr, int cutlength,int position);
int linkStr(char *linkStr,char *cutStr,int linklength,int position);
void clientMsgToASCStr(char *client_Msg);
int createRandomNumber(int randomRange);
void replaceRandomSeed();
typedef big CIPHERTYPE_BIG;

void main(){
	int server_Socket[SOCKNUM];
	int server_Port[SOCKNUM];
	char publicShareKey_KStr[SOCKNUM][CIPHERSIZE];
	char cryptoMessage[CIPHERSIZE];
	struct sockaddr_in server_Sockaddr[SOCKNUM];
	getServerPort(server_Port);
	if(getServerSocket(server_Socket,server_Sockaddr,server_Port)){
		printf("getServerSocket error!\n");
		exit(1);
	}
	if(connectCMix(server_Socket,server_Sockaddr) == -1){
		printf("connectCMix error!\n");
		exit(1);
	}
	mirsys(CIPHERSIZE,DEC);
	for(int i = 0;i < SOCKNUM;i++){
		if(getpublicShareKey(server_Socket[i],publicShareKey_KStr[i]) == -1){
			printf("getpublicShareKey error!\n");
			exit(1);
		}
	}
	encryptoMessage(publicShareKey_KStr,cryptoMessage);
	if(sendAndRecvMessage(server_Socket[SOCKNUM - 1],cryptoMessage) == -1){
		printf("sendAndRecvMessage error!\n");
		exit(1);
	}
	mirexit();
	for(int i = 0;i < MSGNUM;i++){
		close(server_Socket[i]);
	}
}
//*****************************************************************************
//function name:getServerPort()
//in: NULL
//out:int *server_Port
//return:NULL
//*****************************************************************************
void getServerPort(int *server_Port){
	for(int i = 0;i < SOCKNUM;i++){
		*(server_Port + i) = PORT_SERVER + i;
	}
}
//*****************************************************************************
//function name:getServerSocket()
//in: int server_Port[SockNUM]
//out:int *server_Socket
//	  struct sockaddr_in *server_Sockaddr
//return:success:0  error:-1
//*****************************************************************************
int getServerSocket(int *server_Socket,struct sockaddr_in *server_Sockaddr,int server_Port[SOCKNUM]){
	for(int i = 0;i < SOCKNUM;i++){
	    if ((*(server_Socket + i) = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    	{
        	perror("socket");
	        return -1;
    	}
	    (server_Sockaddr + i)->sin_family = AF_INET;
    	(server_Sockaddr + i)->sin_port = htons(server_Port[i]);
		(server_Sockaddr + i)->sin_addr.s_addr = inet_addr("127.0.0.1");
		bzero(&((server_Sockaddr + i)->sin_zero),8);
	}
	return 0;
}
//*****************************************************************************
//function name:connectCMix()
//in :int server_Socket[SOCKNUM]
//	  struct sockaddr_in server_Sockaddr[SOCKNUM]
//out:NULL
//return:success:0  error:-1
//*****************************************************************************
int connectCMix(int server_Socket[SOCKNUM],struct sockaddr_in server_Sockaddr[SOCKNUM]){
	int connect_Overtime;
	for(int i = 0;i < SOCKNUM;i++){
		connect_Overtime = 0;
		while((connect(server_Socket[i], (struct sockaddr *)&server_Sockaddr[i],sizeof(struct sockaddr)) == -1) && (connect_Overtime < OVERTIME))
    	{
			connect_Overtime++;
			sleep(1);
			perror("connect");
    	}
		if(connect_Overtime >= OVERTIME){
			printf("connect overtime!\n");
			return -1;
		}else{
    		printf("conneted to %s,port:%d\n",inet_ntoa(server_Sockaddr[i].sin_addr),server_Sockaddr[i].sin_port);
		}
	}
	return 0;
}
//*****************************************************************************
//function name:getpublicShareKey()
//in :int server_Socket
//out:char *publicShareKey_KStr
//return:success:0  error:-1
//*****************************************************************************
int getpublicShareKey(int server_Socket,char *publicShareKey_KStr){
	char primeNumber_pStr[CIPHERSIZE];
	char primitiveRoot_gStr[MSGSIZE];
	char publicShareKey_YaStr[CIPHERSIZE];
	char publicShareKey_YbStr[CIPHERSIZE];
	CIPHERTYPE_BIG primeNumber_pBig;
	CIPHERTYPE_BIG primitiveRoot_gBig;
	CIPHERTYPE_BIG publicShareKey_YaBig;
	CIPHERTYPE_BIG publicShareKey_YbBig;
	CIPHERTYPE_BIG publicShareKey_XbBig;
	CIPHERTYPE_BIG publicShareKey_KBig;
	primeNumber_pBig = mirvar(0);
	primitiveRoot_gBig = mirvar(0);
	publicShareKey_YaBig = mirvar(0);
	publicShareKey_YbBig = mirvar(0);
	publicShareKey_XbBig = mirvar(0);
	publicShareKey_KBig = mirvar(0);
	replaceRandomSeed();
	if(recvMsg(server_Socket,primeNumber_pStr) == -1){
       	printf("getPublicShareKey_send_primeNumber");
        return -1;
	}
    if(recvMsg(server_Socket,primitiveRoot_gStr) == -1){
	    printf("getPublicShareKey_send_primitiveRoot");
       	return -1;
    }
	if(recvMsg(server_Socket,publicShareKey_YaStr) == -1){
       	printf("getPublicShareKey_send_publicShareKey_YaStr");
        return -1;
	}
	cinstr(primeNumber_pBig,primeNumber_pStr);
	cinstr(primitiveRoot_gBig,primitiveRoot_gStr);
	cinstr(publicShareKey_YaBig,publicShareKey_YaStr);
	bigbits(160,publicShareKey_XbBig);
	powmod(primitiveRoot_gBig,publicShareKey_XbBig,primeNumber_pBig,publicShareKey_YbBig);
	cotstr(publicShareKey_YbBig,publicShareKey_YbStr);
	if(sendMsg(server_Socket,publicShareKey_YbStr) == -1){
       	perror("getPublicShareKey_send_publicShareKey_YbStr");
   	   	return -1;
    }
    powmod(publicShareKey_YaBig,publicShareKey_XbBig,primeNumber_pBig,publicShareKey_KBig);
	cotstr(publicShareKey_KBig,publicShareKey_KStr);
}
//*****************************************************************************
//function name:encryptoMessage()
//in :char publicShareKey_KStr[SOCKNUM][CIPHERSIZE]
//out:char *cryptoMessage
//return:NULL
//*****************************************************************************
void encryptoMessage(char publicShareKey_KStr[SOCKNUM][CIPHERSIZE],char *cryptoMessage){
	char messageStr[CIPHERSIZE];
	CIPHERTYPE_BIG messageBig;
	CIPHERTYPE_BIG publicShareKey_KBig;
	CIPHERTYPE_BIG bignummul_ResultBig;
	messageBig = mirvar(0);
	publicShareKey_KBig = mirvar(0);
	bignummul_ResultBig = mirvar(0);
	printf("input your message:");
	fgets(messageStr,MSGSIZE,stdin);
	clientMsgToASCStr(messageStr);
	cinstr(messageBig,messageStr);
	for(int i = 0;i < SOCKNUM;i++){
		cinstr(publicShareKey_KBig,publicShareKey_KStr[i]);
		multiply(messageBig,publicShareKey_KBig,bignummul_ResultBig);
		copy(bignummul_ResultBig,messageBig);
	}
	cotstr(messageBig,cryptoMessage);
}
//*****************************************************************************
//function name:sendAndRecvMessage()
//in :int serverSocket
//	  char cryptoMessage[CIPHERSIZE]
//out:NULL
//return:success:0  error:-1
//*****************************************************************************
int sendAndRecvMessage(int serverSocket,char cryptoMessage[CIPHERSIZE]){
	char recvMessage[MSGSIZE];
	if(sendMsg(serverSocket,cryptoMessage) == -1){
		printf("sendAndRecvMessage_send!");
		return -1;
	}
	printf("waiting recv!\n");
	if(recv(serverSocket,recvMessage,MSGSIZE,0) == -1){
		printf("sendAndRecvMessage_recv!");
		return -1;
	}
	printf("recv:%s\n",recvMessage);
	return 0;
}
//**************************************************************************
//function name:sendnextMsg()
//in : int next_Socket
//out: char next_Msg[CIPHERSIZE]
//return: success:0  error:-1
//author:btlshow
//First Edition:2018.7.21 Sat 14:50
//Last Edition: 2018.8.12 Mon 19:42 
//**************************************************************************
int sendnextMsg(int next_Socket,char (*next_Msg)[CIPHERSIZE]){
	for(int i = 0;i < MSGNUM;i++){
		if(sendMsg(next_Socket,next_Msg[i]) == -1){
			printf("sendnextMsg %d error\n",i);
			return -1;
		}
	}
	return 0;
}
//**************************************************************************
//function name:sendMsg()
//in : int next_Socket
//out: char next_Msg[CIPHERSIZE]
//return: success:0  error:-1
//author:btlshow
//First Edition:2018.7.21 Sat 14:50
//Last Edition: 2018.8.12 Mon 19:42 
//**************************************************************************
int sendMsg(int next_Socket,char next_Msg[CIPHERSIZE]){
	int msgLength = strlen(next_Msg);
	int sendNum = ((msgLength % MSGSIZE) == 0) ? (msgLength / MSGSIZE) : (msgLength / MSGSIZE + 1);
	char sendNumStr[3];
	char msgStr[MSGSIZE + 1];
	sprintf(sendNumStr,"%d",sendNum);
	if(send(next_Socket, sendNumStr, 3, 0) == -1){
        perror("send");
        return -1;
	}
    for(int i = 0;i < sendNum;i++){
    	if (cutStr(next_Msg,msgStr,MSGSIZE,i * MSGSIZE) == -1){
    		printf("error in cut Str\n");
    		return -1;
		}
        if (send(next_Socket, msgStr, MSGSIZE + 1, 0) == -1){
            perror("send");
            return -1;
		}
    }
	return 0;
}
//**************************************************************************
//function name:recvpriorMsg()
//in : int prior_Socket
//out: char prior_Msg[CIPHERSIZE]
//return: success:0  error:-1
//author:btlshow
//First Edition:2018.7.21 Sat 14:50
//Last Edition: 2018.8.12 Mon 20:42 
//**************************************************************************
int recvpriorMsg(int prior_Socket,char (*prior_Msg)[CIPHERSIZE]){
	for(int i = 0;i < MSGNUM;i++){
		if(recvMsg(prior_Socket,prior_Msg[i]) == -1){
			printf("recvpriorMsg %d error\n",i);
			return -1;
		}
	}
	return 0;
}
//**************************************************************************
//function name:recvMsg()
//in : int prior_Socket
//out: char prior_Msg[CIPHERSIZE]
//return: success:0  error:-1
//author:btlshow
//First Edition:2018.7.21 Sat 14:50
//Last Edition: 2018.8.12 Mon 19:42 
//**************************************************************************
int recvMsg(int prior_Socket,char* prior_Msg){
	char msgStr[MSGSIZE + 1];
	char recvNumStr[3];
	int recvNum;
	int numberByte;
	if(recv(prior_Socket,recvNumStr,3,0) == -1){
		perror("recv");
        return -1;
	}
	recvNum = atoi(recvNumStr);
	for(int i = 0;i < recvNum;i++){
		if((numberByte = recv(prior_Socket,msgStr,MSGSIZE + 1,0))== -1){
		perror("recv");
        return -1;
		}
		msgStr[numberByte] = '\0';
		if(linkStr(prior_Msg,msgStr,MSGSIZE,i * MSGSIZE) == -1){
			printf("error in link str!\n");
			return -1;
		}
	}
	return 0;
}
//**************************************************************************
//function name:cutStr()
//in : int cutlength
//     int position
//	   char *origStr
//out: char *cutStr
//return: success:0  error:-1
//author:btlshow
//First Edition:2018.7.21 Sat 14:50
//Last Edition: 2018.8.12 Mon 19:42 
//**************************************************************************
int cutStr(char *origStr,char *cutStr, int cutlength,int position){
    char *p = origStr;
    char *q = cutStr;
    int origStrlen = strlen(p);
    if(cutlength > origStrlen){
		cutlength = origStrlen - position;
	}
    if(position < 0){
    	printf("position:%d\n",position);
		return -1;
	}
    if(position > origStrlen) {
    	printf("position:%d  origStrlen:%d\n",position,origStrlen);
    	return -1;
	}		
    p += position;
    while(cutlength--){
		*(q++) = *(p++);
	}
	*(q++) = '\0';
    return 0;
}
//**************************************************************************
//function name:linkStr()
//in : int position
//	   int linklength
//	   char *cutStr
//out: char *linkStr
//return: success:0  error:-1
//author:btlshow
//First Edition:2018.7.21 Sat 14:50
//Last Edition: 2018.8.12 Mon 19:42 
//**************************************************************************
int linkStr(char *linkStr,char *cutStr,int linklength,int position){
    char *p = linkStr;
    char *q = cutStr;
    int cutStrlen = strlen(q);
    if(linklength > cutStrlen){
		linklength = cutStrlen;
	}
    if(position < 0){
    	printf("position:%d\n",position);    	
		return -1;
	}
    p += position;
    while(linklength--){
		*(p++) = *(q++); 
	}
	*(p++) = '\0';
    return 0;
}
//**************************************************************************
//function name:clientMsgToASCStr()
//in :NULL
//out:char *client_Msg
//return:NULL
//author:btlshow
//first Edition:2018.8.4 Sat 22:23
//last Edition: 2018.8.4 Sat 22:40
//**************************************************************************
void clientMsgToASCStr(char *client_Msg){
    char msg_Str[CIPHERSIZE];
    char singlechar_ASCStr[4];
    int singlechar_ASC;
    strcpy(msg_Str,client_Msg);
    for(int i = 0;i < strlen(msg_Str);i++){
        singlechar_ASC = msg_Str[i];
        sprintf(singlechar_ASCStr,"%d",singlechar_ASC);
        for(int j = 0;j < (3 - strlen(singlechar_ASCStr));j++){
            singlechar_ASCStr[2] = singlechar_ASCStr[1];
            singlechar_ASCStr[1] = singlechar_ASCStr[0];
            singlechar_ASCStr[0] = '0';
        }
        for(int k = 0;k < 3;k++){
            *(client_Msg + 3 * i + k + 1) = *(singlechar_ASCStr + k);
        }
    }
	*(client_Msg) = '1';
    *(client_Msg + 3 * strlen(msg_Str) + 1)='\0';
}

//**************************************************************************
//function name:createRandomNumber()
//in :NULL
//out:NULL
//return:int randomNum
//author:btlshow
//first Edition:2018.7.26 Thu 19.10
//Last Edition: 2018.7.26 Thu 19.10
//**************************************************************************
int createRandomNumber(int randomRange){
	int *p;
    p = (int*)malloc(sizeof(int));
    srand((unsigned long)p);
    int original_Num = rand() % randomRange;
    if(original_Num < 10){
        return createRandomNumber(randomRange);
    }else{
        return original_Num;
    }
}
//**************************************************************************
//function name:replaceRandomSeed()
//in :NULL
//out:NULL
//return:NULL
//author:btlshow
//first Edition:2018.7.26 Thu 19.10
//Last Edition: 2018.8.14 Tue 21.10
//**************************************************************************
void replaceRandomSeed(){
	time_t seed;
	time(&seed);
    irand((unsigned long)seed);
}
