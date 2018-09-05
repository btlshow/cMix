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
#include <pthread.h>

#define CIPHERTYPE_SHORT unsigned int
#define CIPHERTYPE_LONG unsigned long long int
#define MSGSIZE 4092
#define CIPHERSIZE 4092
#define BACKLOG 10
#define MSGNUM 5 
#define MYPORT_MIXNODE 38080
#define MYPORT_CLIENT 38090
#define RANDOMRANGE 100
#define PRIMITIVEROOT_G 3
#define MIXNODENUM 3 
#define DEC 10

typedef big CIPHERTYPE_BIG;

int connectWithNextAndPriorSocket(int argc,char* argv[4],int *mixnode_Port,char* next_Address,unsigned int* next_Port,unsigned int *my_Port,\
		int* mixnode_Type,int *my_Socket,int* prior_Socket,int* next_Socket,struct sockaddr_in *prior_Sockaddr,\
		struct sockaddr_in *my_Sockaddr,struct sockaddr_in *next_Sockaddr);
void *connectNextSocket(void *args);
int getInitialData(int argc,char* argv[4],char* next_Address,unsigned int* next_Port,unsigned int *my_Port,int* mixnode_Port,\
		int* mixnode_Type);
void setmySockaddr(struct sockaddr_in* my_Sockaddr,unsigned int port);
void setnextSockaddr(struct sockaddr_in* next_Sockaddr,char* next_Address,unsigned int next_Port);
int acceptpriorSocket(int my_Socket,int* prior_Socket,struct sockaddr_in* prior_Sockaddr);
int sendnextMsg(int next_Socket,char (*next_Msg)[CIPHERSIZE]);
int sendMsg(int next_Socket,char next_Msg[CIPHERSIZE]);
int recvpriorMsg(int prior_Socket,char (*prior_Msg)[CIPHERSIZE]);
int recvMsg(int prior_Socket,char* prior_Msg);
int cutStr(char *origStr,char *cutStr, int cutlength,int position);
int linkStr(char *linkStr,char *cutStr,int linklength,int position);
int setupCMix(CIPHERTYPE_SHORT *secret_ShareKey_di,char (*public_ShareKey_KStr)[CIPHERSIZE],char *publicKey_eStr,\
		int mixnode_Type,int my_Socket,int next_Socket,int prior_Socket,int *client_Socket,CIPHERTYPE_SHORT *groupG_Generator_g);
int getGroupGGenerator(CIPHERTYPE_SHORT *groupG_Generator_g,int prior_Socket,int next_Socket,int mixnode_Type);
int getincompletePublicKey(CIPHERTYPE_SHORT *secret_ShareKey_di,int mixnode_Type,int prior_Socket,\
		char *incomplete_PublicKey_eStr,CIPHERTYPE_SHORT groupG_Generator_g);
int sendincompletePublicKey(char *incomplete_PublicKey_eStr,int next_Socket,int mixnode_Type);
int getPublicKey(char *publicKey_eStr,int prior_Socket,int next_Socket,int mixnode_Type);
int connectWithClient(char (*public_ShareKey_KStr)[CIPHERSIZE],int mixnode_Type,int my_Socket,int *client_Socket);
int getPublicShareKey(char *public_ShareKey_KStr,CIPHERTYPE_SHORT primitiveRoot_g,int client_Socket);
int precomputationPreprocessing(int mixnode_Type,int prior_Socket,int next_Socket,CIPHERTYPE_SHORT groupG_Generator_g,\
		char (*processing_Value_RStr)[CIPHERSIZE],char (*processing_Value_SStr)[CIPHERSIZE],\
		char (*processing_Value_XStr)[CIPHERSIZE],char *publicKey_eStr);
int setPrecomputationInitialValue(int mixnode_Type,int prior_Socket,int next_Socket,char (*processing_Value_RStr)[CIPHERSIZE],\
		char (*processing_Value_SStr)[CIPHERSIZE],char(*processing_Value_XStr)[CIPHERSIZE]);
int precomputationMixing(int* Pi_NumberGroup,int prior_Socket,int next_Socket,CIPHERTYPE_SHORT groupG_Generator_g,\
        char publicKey_eStr[CIPHERSIZE],char (*processing_Value_SStr)[CIPHERSIZE],char (*processing_Value_XStr)[CIPHERSIZE]);
void disorderOrderNumberGroup(int* disorder_NumberGroup);
int precomputationPostprocessing(int prior_Socket,int next_Socket,int mixnode_Type,CIPHERTYPE_SHORT secret_ShareKey_di,\
        char (*plainText_PiRSStr)[CIPHERSIZE]);
int realtimeProcessing(int prior_Socket,int next_Socket,int *client_Socket,int mixnode_Type,CIPHERTYPE_SHORT groupG_Generator_g,\
        char publickey_eStr[CIPHERSIZE],char (*public_ShareKey_KStr)[CIPHERSIZE],char processing_Value_XStr[MSGNUM][CIPHERSIZE],\
        char processing_Value_RStr[MSGNUM][CIPHERSIZE]);
int realtimeProcessingEncryptoMsg(char (*prior_realtime_EncryptoMsgStr)[CIPHERSIZE],char(*realtime_EncryptoMsgStr)[CIPHERSIZE],\
        char public_ShareKey_KStr[MSGNUM][CIPHERSIZE],char processing_Value_RStr[MSGNUM][CIPHERSIZE]);
int getClientMsg(int *client_Socket,char (*prior_Msg)[CIPHERSIZE]);
int acceptClientSocket(int my_Socket,int *client_Socket);
int realtimeMixing(int prior_Socket,int next_Socket,int client_Socket[MSGNUM],int mixnode_Type,int *Pi_NumberGroup,\
        CIPHERTYPE_SHORT groupG_Generator_g,char publicKey_eStr[CIPHERSIZE],char processing_Value_SStr[MSGNUM][CIPHERSIZE],\
		char processing_Value_XStr[MSGNUM][CIPHERSIZE],char (*plainText_PiRSStr)[CIPHERSIZE]);
void realtimeMixingEncryptoMsg(int Pi_NumberGroup[MSGNUM],char (*prior_realtime_EncryptoMsgStr)[CIPHERSIZE],\
        char (*realtime_EncryptoMsgStr)[CIPHERSIZE],char processing_Value_SStr[MSGNUM][CIPHERSIZE]);
int sendMsgToClient(char plainText_PiRSStr[MSGNUM][CIPHERSIZE],int client_Socket[MSGNUM]);
int realtimePostprocessing(int next_Socket,char (*cryptoMessage)[CIPHERSIZE],char (*plainText_PiRSStr)[CIPHERSIZE]);
void calculateProcessingEncrypto(char (*processing_Value_RStr)[CIPHERSIZE],char (*processing_Value_XStr)[CIPHERSIZE],char *publicKey_eStr,\
        char prior_cryptoProcessing_ValueStr[MSGNUM][CIPHERSIZE],char cryptoProcessing_ValueStr[MSGNUM][CIPHERSIZE]);
void calculateMixingEncrypto(char (*processing_Value_SStr)[CIPHERSIZE],char (*processing_Value_XStr)[CIPHERSIZE],char *publicKey_eStr,\
        char prior_cryptoMixing_ValueStr[MSGNUM][CIPHERSIZE],int Pi_NumberGroup[MSGNUM],char (*cryptoMixing_ValueStr)[CIPHERSIZE]);
void calculateProcessingGX(CIPHERTYPE_SHORT groupG_Generator_g,char processing_Value_XStr[MSGNUM][CIPHERSIZE],\
        char prior_gXStr[MSGNUM][CIPHERSIZE],char (*result_gXStr)[CIPHERSIZE]);
void calculateMixingGX(CIPHERTYPE_SHORT groupG_Generator_g,char processing_Value_XStr[MSGNUM][CIPHERSIZE],int Pi_NumberGroup[MSGNUM],\
        char prior_gXStr[MSGNUM][CIPHERSIZE],char (*result_gXStr)[CIPHERSIZE]);
int getInverse(char orignNumberStr[CIPHERSIZE],char primeNumberStr[CIPHERSIZE],char* inverseNumberStr);
void extGcd(char orignNumberStr[CIPHERSIZE],char primeNumberStr[CIPHERSIZE],char* dStr,char* xStr,char* yStr);
int createRandomNumber(int randomRange);
char* getPrimeNumber();
void replaceRandomSeed();
void clientMsgToASCStr(char *client_Msg);
int ascStrToClientMsg(char *ascStr);
//*************************************************************************
//funtion name:main()
//in : int argc
//     char* argv[] 4
//out: NULL
//return: success:1  error:-1
//author:btlshow
//First Edition:2018.7.20 Fri 17:10
//Last Edition: 2018.8.08 Wed 15:34
//*************************************************************************
int main(int argc,char* argv[]){
	int my_Socket,next_Socket,prior_Socket;
	int client_Socket[MSGNUM];
	int mixnode_Port[MIXNODENUM];
	int mixnode_Type; //1:the First 2:normal 3:the Last
	unsigned int next_Port,my_Port;	
	char next_Address[16];
	struct sockaddr_in my_Sockaddr,next_Sockaddr,prior_Sockaddr;
	char prior_Msg[MSGNUM][MSGSIZE],next_Msg[MSGNUM][MSGSIZE];
	int Pi_NumberGroup[MSGNUM];
    CIPHERTYPE_SHORT secret_ShareKey_di;
    CIPHERTYPE_SHORT groupG_Generator_g;
	char processing_Value_XStr[2 * MSGNUM][CIPHERSIZE];
    char processing_Value_RStr[MSGNUM][CIPHERSIZE],processing_Value_SStr[MSGNUM][CIPHERSIZE];
    char public_ShareKey_KStr[MSGNUM][CIPHERSIZE];
	char publicKey_eStr[CIPHERSIZE];
	char plainText_PiRSStr[MSGNUM][CIPHERSIZE];	
	
	if(connectWithNextAndPriorSocket(argc,argv,mixnode_Port,next_Address,&next_Port,&my_Port,&mixnode_Type,&my_Socket,\
			&prior_Socket,&next_Socket,&my_Sockaddr,&prior_Sockaddr,&next_Sockaddr) == -1){
		printf("connectWithNextAndPriorSocket error!\n");
		exit(1);
	}
	if(setupCMix(&secret_ShareKey_di,public_ShareKey_KStr,publicKey_eStr,mixnode_Type,my_Socket,next_Socket,prior_Socket,\
				client_Socket,&groupG_Generator_g) == -1){
		printf("setupCMix error!\n");
		exit(1);
	}
	if(precomputationPreprocessing(mixnode_Type,prior_Socket,next_Socket,groupG_Generator_g,processing_Value_RStr,processing_Value_SStr,\
				processing_Value_XStr,publicKey_eStr) == -1){
		printf("precomputationPreprocessing error!\n");
		exit(1);
	}
	if(precomputationMixing(Pi_NumberGroup,prior_Socket,next_Socket,groupG_Generator_g,publicKey_eStr,processing_Value_SStr,\
				processing_Value_XStr) == -1){
		printf("precomputationMixing error!\n");
		exit(1);
	}
	if(precomputationPostprocessing(prior_Socket,next_Socket,mixnode_Type,secret_ShareKey_di,plainText_PiRSStr) == -1){
		printf("precomputationPostprocessing error!\n");
		exit(1);
	}
	if(realtimeProcessing(prior_Socket,next_Socket,client_Socket,mixnode_Type,groupG_Generator_g,publicKey_eStr,\
        public_ShareKey_KStr,processing_Value_XStr,processing_Value_RStr) == -1){
		printf("realtimeProcessing error!\n");
		exit(1);
	}
	if(realtimeMixing(prior_Socket,next_Socket,client_Socket,mixnode_Type,Pi_NumberGroup,groupG_Generator_g,publicKey_eStr,\
				processing_Value_SStr,processing_Value_XStr,plainText_PiRSStr) == -1){
		printf("realtimeMixing error!\n");
		exit(1);
	}
	close(my_Socket);
}

//**************************************************************************
//function name:connectWithNextAndPriorSocket()
//in :int argc
//	  char *argv[4]
//out:char* next_Address
//	  unsigned int* next_Port
//	  unsigned int* my_Port
//	  int *mixnode_Type
//	  int *my_Socket
//	  int *prior_Socket
//	  int *next_Socket
//	  struct sockaddr_in *my_Sockaddr
//	  struct sockaddr_in *prior_Sockaddr
//	  struct sockaddr_in *next_Sockaddr
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.8.06 Mon 14:52
//last Edition: 2018.8.08 Wed 15:31
//**************************************************************************
struct connectArgPointer{
	unsigned int next_Socket;
	struct sockaddr_in *next_Sockaddr;
};

int connectWithNextAndPriorSocket(int argc,char* argv[4],int *mixnode_Port,char* next_Address,unsigned int* next_Port,unsigned int *my_Port,\
		int* mixnode_Type,int *my_Socket,int* prior_Socket,int* next_Socket,struct sockaddr_in *prior_Sockaddr,\
		struct sockaddr_in *my_Sockaddr,struct sockaddr_in *next_Sockaddr){
	struct connectArgPointer connect_ArgPointer;
	void *returnNumber;
	pthread_t thread_ConnectNextSocket;
	if(getInitialData(argc,argv,next_Address,next_Port,my_Port,mixnode_Port,mixnode_Type) == -1){
		printf("connectWithNextAndPriorSocket_getInitialData error!\n");
		return -1;
	}
	if((*my_Socket = socket(AF_INET,SOCK_STREAM,0)) == -1){
        perror("connectWithNextAndPriorSocket_my_Socket error");
        return -1;
    }
	setmySockaddr(my_Sockaddr,*my_Port);
    if((bind(*my_Socket,(struct sockaddr*)my_Sockaddr,sizeof(struct sockaddr))) == -1){
        perror("connectWithNextAndPriorSocket_bind error");
        return -1;
    }
    if(listen(*my_Socket,BACKLOG) == -1){
        perror("connectWithNextAndPriorSocket_listen error");
        return -1;
    }
	if((*next_Socket = socket(AF_INET,SOCK_STREAM,0)) == -1){
        perror("connectWithNextAndPriorSocket_next_Socket error");
        return -1;
	}
    setnextSockaddr(next_Sockaddr,next_Address,*next_Port);
	connect_ArgPointer.next_Socket = *next_Socket;
	connect_ArgPointer.next_Sockaddr = next_Sockaddr;
	if(pthread_create(&thread_ConnectNextSocket, NULL, connectNextSocket, &connect_ArgPointer) != 0)
    {
	    printf("ERROR; wrong thread\n");
        return -1;
    }
	if(acceptpriorSocket(*my_Socket,prior_Socket,prior_Sockaddr) == -1){
        printf("connectWithNextAndPriorSocket_acceptpriorSocket error!\n");
        return -1;
    }
    pthread_join(thread_ConnectNextSocket, &returnNumber);
    if ((long long int)returnNumber == -1){
        printf("pthread error!\n");
        return -1;
    }
	return 0;
}

//*************************************************************************
//function name:connectNextSocket()
//in: void args   struct connectArgPointer
//out:NULL
//return:NULL   exit():error: -1
//author:btlshow
//first Edition:2018.8.8 Wed 15:20
//last Edition: 2018.8.8 Wed 18:46
//*************************************************************************
void *connectNextSocket(void *args){
	long long int returnNumber = 0;
	int connectingTime = 100;
    struct connectArgPointer *thread_arg;
    thread_arg = ((struct connectArgPointer*)args);
	while((connect(thread_arg->next_Socket,(struct sockaddr *)(thread_arg->next_Sockaddr),sizeof(struct sockaddr)) == -1)&&(connectingTime > 0)){
        printf("connectWithNextAndPriorSocket_connect failed!\n");
        connectingTime--;
        sleep(1);
    }   
    if(connectingTime > 0){ 
        printf("connectnext with:%s Port:%d\n",inet_ntoa((thread_arg->next_Sockaddr)->sin_addr),thread_arg->next_Sockaddr->sin_port);
    }else{
        printf("connectWithNextAndPriorSocket_connect overTime!\n");
		returnNumber = -1;
		pthread_exit((void *)returnNumber);
    }
    return NULL;
}

//**************************************************************************
//funtion name:getInitialData()
//in : int argc 
//     char argv[4]
//out: char* next_Address
//     unsigned int next_Port
//     unsigned int my_Port
//     int *mixnode_Port
//	   int mixnode_Type
//return: success:0  error:-1
//author:btlshow
//First Edition:2018.7.20 Fri 17:30
//Last Edition: 2018.7.26 Thu 17:20
//**************************************************************************
int getInitialData(int argc,char* argv[4],char* next_Address,unsigned int* next_Port,unsigned int *my_Port,int* mixnode_Port,\
		int* mixnode_Type){
	struct hostent* temphostent;
	char* addressstr;
	int next_PortNum;
	if (argc != 4){
		printf("invalid input\n");
		return -1;
	}
	if ((gethostbyname(argv[1])->h_name) == NULL){
		perror("gethostbyname\n");
		return -1;
	}else{
		int i;
		for(i = 0;i < strlen(argv[1]);i++){
			*(next_Address + i) = *(argv[1] + i);
		}
		*(next_Address + i)='\0';
	}
	next_PortNum = atoi(argv[2]);
	if ((next_PortNum == 0) || (next_PortNum > MIXNODENUM)){
        printf("invalid Port\n");
        return -1;
    }else{
		for(int i = 0;i < MIXNODENUM;i++){
    	    *(mixnode_Port + i) = MYPORT_MIXNODE + i;
   		}
		*next_Port = *(mixnode_Port + next_PortNum - 1);
		if(next_PortNum == 1){
			*my_Port = *(mixnode_Port + MIXNODENUM - 1);
		}else{
			*my_Port = *next_Port - 1;
		}
		printf("next_Port:%d  my_Port:%d\n",*next_Port,*my_Port);
	}
	*mixnode_Type = atoi(argv[3]);
	if((*mixnode_Type!=1)&&(*mixnode_Type!=2)&&(*mixnode_Type!=3)){
		printf("invalid input\n");
		mixnode_Type=0;
		return -1;
	}else{
		printf("mixnode_Type:%d\n",*mixnode_Type);
	}
	return 0;
}

//*************************************************************************
//function name:setmySockaddr()
//in :unsigned int port
//out:struct Sockaddr_in my_Sockaddr
//return: NULL
//author:btlshow
//First Edition:2018.7.20 Fri 19:54
//Last Edition: 2018.8.08 Wed 15:34
//**************************************************************************
void setmySockaddr(struct sockaddr_in* my_Sockaddr,unsigned int port){
	my_Sockaddr->sin_family = AF_INET;
	my_Sockaddr->sin_port = htons(port);
	my_Sockaddr->sin_addr.s_addr = INADDR_ANY;
	bzero(&(my_Sockaddr->sin_zero),8);
}

//**************************************************************************
//function name:setnextSockaddr()
//in : unsigned int next_Port
//     char* next_Address
//out: struct Sockaddr_in next_Sockaddr
//return: NULL
//author:btlshow
//First Edition:2018.7.20 Fri 20:30
//Last Edition: 2018.7.26 Thu 15:46
//**************************************************************************
void setnextSockaddr(struct sockaddr_in* next_Sockaddr,char* next_Address,unsigned int next_Port){
	next_Sockaddr->sin_family = AF_INET;
	next_Sockaddr->sin_addr.s_addr = inet_addr(next_Address);
	next_Sockaddr->sin_port=htons(next_Port);
	bzero(&(next_Sockaddr->sin_zero),8);
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
    	if(cutStr(next_Msg,msgStr,MSGSIZE,i * MSGSIZE) == -1){
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
int recvpriorMsg(int prior_Socket,char(*prior_Msg)[CIPHERSIZE]){
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
//function name:acceptpriorSocket()
//in : int my_socket
//out: struct sockaddr_in prior_Sockaddr
//     int prior_Socket
//return: success:0  error:-1
//author:btlshow
//First Edition:2018.7.22 Sun 20:38
//Last Edition: 2018.7.23 Mon 09:47
//**************************************************************************
int acceptpriorSocket(int my_Socket,int* prior_Socket,struct sockaddr_in* prior_Sockaddr){
	int sockaddr_Size = sizeof(struct sockaddr_in);
	int accept_Num = 0;
	while(accept_Num < MSGNUM){
        if((*prior_Socket = accept(my_Socket,(struct sockaddr*)prior_Sockaddr,&sockaddr_Size)) < 0){
            perror("accept");
            continue;
        }else{
            printf("connect prior to %s,port:%d\n",inet_ntoa(prior_Sockaddr->sin_addr),prior_Sockaddr->sin_port);
            return 0;
        }
		accept_Num++;
    }
	return -1;
}

//**************************************************************************
//function name:setupCMix()
//in :int mixnode_Type
//	  int my_Socket
//	  int next_Sockey
//	  int prior_Socket
//out:CIPHERTYPE_SHORT secret_ShareKey_di
//	  CIPHERTYPE_SHORT groupG_Generator_g
//	  char (*public_ShareKey_KStr)[CIPHERSIZE]
//	  char* publicKey_eStr
//return:success:0  error:-1
//author:btlshow	
//first Edition:2018.7.26 Thu 21:22
//last Edition: 2018.8.14 Tue 22:37
//**************************************************************************
int setupCMix(CIPHERTYPE_SHORT *secret_ShareKey_di,char (*public_ShareKey_KStr)[CIPHERSIZE],char *publicKey_eStr,\
		int mixnode_Type,int my_Socket,int next_Socket,int prior_Socket,int *client_Socket,CIPHERTYPE_SHORT *groupG_Generator_g){
	char incomplete_PublicKey_eStr[CIPHERSIZE];
	if(getGroupGGenerator(groupG_Generator_g,prior_Socket,next_Socket,mixnode_Type) == -1){
		printf("getGroupGenerator error!\n");
		return -1;
	}
	if(getincompletePublicKey(secret_ShareKey_di,mixnode_Type,prior_Socket,incomplete_PublicKey_eStr,*groupG_Generator_g) == -1){
		printf("getincompletePublicKey error!\n");
		return -1;
	}
	if(sendincompletePublicKey(incomplete_PublicKey_eStr,next_Socket,mixnode_Type) == -1){
		printf("sendincompletePublicKey error!\n");
		return -1;
	}
	if(getPublicKey(publicKey_eStr,prior_Socket,next_Socket,mixnode_Type) == -1){
		printf("getPublicKey error!\n");
		return -1;
	}
	printf("getPublicKey!\n");
	if(connectWithClient(public_ShareKey_KStr,mixnode_Type,my_Socket,client_Socket) == -1){
		printf("connectWithClient error!\n");
		return -1;
	}
	printf("complete setup CMix!\n");
	return 0;
}

//**************************************************************************
//function name:getGroupGGenerator()
//in :int prior_Socket
//	  int next_Socket
//	  int mixnode_Type
//out:int groupG_Generator_g
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.26 Thu 21.30
//last Edition: 2018.7.27 Fri 16.42
//**************************************************************************
int getGroupGGenerator(CIPHERTYPE_SHORT *groupG_Generator_g,int prior_Socket,int next_Socket,int mixnode_Type){
	char groupG_Generator_gStr[3];
	if(mixnode_Type != 1){
		if(recv(prior_Socket,groupG_Generator_gStr,3,0) == -1){
			perror("getGroupGGenerator_recv_groupG_Generator_g");
			return -1;
		}
		if(mixnode_Type != 3){
			if(send(next_Socket,groupG_Generator_gStr,3,0) == -1){
            	perror("getGroupGGenerator_send_groupG_Generator_g");
       		    return -1;
        	}
		}
		*groupG_Generator_g = atoi(groupG_Generator_gStr);
	}else{
		*groupG_Generator_g = createRandomNumber(RANDOMRANGE);
		sprintf(groupG_Generator_gStr,"%d",*groupG_Generator_g);
		if(send(next_Socket,groupG_Generator_gStr,3,0) == -1){
			perror("getGroupGGenerator_send_groupG_Generator_g");
			return -1;
		}
	}
	return 0;
}

//**************************************************************************
//function name:getincompletePublicKey()
//in :int mixnode_Type
//    int prior_Socket
//    CIPHERTYPE_SHORT groupG_Generator_g
//out:CIPHERTYPE_SHORT secret_ShareKey_di
//    char incomplete_PublicKey_eStr
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.27 Fri 16:50
//last Edition: 2018.7.31 Tue 14:46
//**************************************************************************
int getincompletePublicKey(CIPHERTYPE_SHORT *secret_ShareKey_di,int mixnode_Type,int prior_Socket,\
		char *incomplete_PublicKey_eStr,CIPHERTYPE_SHORT groupG_Generator_g){
    *secret_ShareKey_di = createRandomNumber(RANDOMRANGE);
    mirsys(CIPHERSIZE,DEC);
	char prior_PublicKey_eStr[CIPHERSIZE];
	CIPHERTYPE_BIG prior_PublicKey_eBig;
	CIPHERTYPE_BIG groupG_Generator_gBig;
	CIPHERTYPE_BIG secret_ShareKey_diBig;
	CIPHERTYPE_BIG bignumpow_ResultBig;
	CIPHERTYPE_BIG bignummod_ResultBig;
	CIPHERTYPE_BIG incomplete_PublicKey_eBig;
	CIPHERTYPE_BIG primeNumber_pBig;
	prior_PublicKey_eBig = mirvar(0);
    groupG_Generator_gBig = mirvar(0);
    bignumpow_ResultBig = mirvar(0);
	bignummod_ResultBig = mirvar(0);
	secret_ShareKey_diBig = mirvar(0);
    incomplete_PublicKey_eBig = mirvar(0);
	primeNumber_pBig = mirvar(0);
	*secret_ShareKey_di = createRandomNumber(RANDOMRANGE);
	convert(groupG_Generator_g,groupG_Generator_gBig);
	convert(*secret_ShareKey_di,secret_ShareKey_diBig);
	cinstr(primeNumber_pBig,getPrimeNumber());
	powmod(groupG_Generator_gBig,secret_ShareKey_diBig,primeNumber_pBig,bignumpow_ResultBig);
    if(mixnode_Type != 1){
        if(recvMsg(prior_Socket,prior_PublicKey_eStr) == -1){
            perror("getincompletePublicKeyrecv_prior_PublicKey_eStr");
            return -1;
        }
		cinstr(prior_PublicKey_eBig,prior_PublicKey_eStr);
		multiply(prior_PublicKey_eBig,bignumpow_ResultBig,incomplete_PublicKey_eBig);
		divide(incomplete_PublicKey_eBig,primeNumber_pBig,bignummod_ResultBig);
		cotstr(incomplete_PublicKey_eBig,incomplete_PublicKey_eStr);
    }else{
    	cotstr(bignumpow_ResultBig,incomplete_PublicKey_eStr);
	}
	mirexit();
	return 0;
}

//**************************************************************************
//function:sendincompletePublicKey()
//in :int mixnode_Type
//	  int next_Socket
//	  int mixnode_type
//out:char *incomplete_PublicKey_eStr
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.31 Tue 16:40
//last Edition: 2018.7.31 Tue 17:02
//**************************************************************************
int sendincompletePublicKey(char *incomplete_PublicKey_eStr,int next_Socket,int mixnode_Type){
    if(sendMsg(next_Socket,incomplete_PublicKey_eStr) == -1){
 	   perror("sendincompletePublicKeysend_incomplete_publicKey_eStr");
       return -1;
	}
    return 0;
}

//**************************************************************************
//function:getPublicKey()
//in :int Prior_Socket
//	  int next_Socket
//	  int mixnode_Type
//out:char *publicKey_eStr
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.26 Thu 21.30
//last Edition: 2018.8.11 Sat 18.37
//**************************************************************************
int getPublicKey(char *publicKey_eStr,int prior_Socket,int next_Socket,int mixnode_Type){
	if(recvMsg(prior_Socket,publicKey_eStr) == -1){
		perror("getPublicKeyrecv");
		return -1;
	}
	if(mixnode_Type != 3){
		if(sendMsg(next_Socket,publicKey_eStr) == -1){
			perror("getPublicKeysend");
			return -1;
		}
	}
	return 0;
}

//**************************************************************************
//function name:connectWithClient()
//in :int mixnode_Type
//	  int my_Socket
//out:char (*public_ShareKey_KStr)[CIPHERSIZE]
//	  int *client_Socket
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.26 Thu 20:25
//last Edition: 2018.8.09 Thu 10:22
//**************************************************************************
int connectWithClient(char (*public_ShareKey_KStr)[CIPHERSIZE],int mixnode_Type,int my_Socket,int *client_Socket){
    int primitiveRoot_g;
    primitiveRoot_g = PRIMITIVEROOT_G;
	if(acceptClientSocket(my_Socket,client_Socket) == -1){
		printf("acceptClientSocket error!\n");
		return -1;
	}
	for(int i = 0;i < MSGNUM;i++){
        if(getPublicShareKey(public_ShareKey_KStr[i],primitiveRoot_g,client_Socket[i]) == -1){
            printf("getPublicShareKey error!\n");
            return -1;
		}
    }
	return 0;
}

//**************************************************************************
//function:getPublicShareKey()
//in :int client_Socket
//	  CIPHERTYPE_SHORT primeNumber_p
//	  CIPHERTYPE_SHORT primitiveRoot_g
//out:char *public_ShareKey_KStr
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.26 Thu 21:30
//last Edition: 2018.7.31 Tue 21:08
//**************************************************************************
int getPublicShareKey(char *public_ShareKey_KStr,CIPHERTYPE_SHORT primitiveRoot_g,int client_Socket){
	CIPHERTYPE_BIG publicShareKey_YaBig;
    CIPHERTYPE_BIG publicShareKey_YbBig;
	CIPHERTYPE_BIG publicShareKey_XaBig;
	CIPHERTYPE_BIG primeNumber_pBig;
	CIPHERTYPE_BIG primitiveRoot_gBig;
	CIPHERTYPE_BIG public_ShareKey_KBig;	
	char primeNumber_pStr[CIPHERSIZE];
	char primitiveRoot_gStr[CIPHERSIZE];
	char publicShareKey_YaStr[CIPHERSIZE];
	char publicShareKey_YbStr[CIPHERSIZE];
	mirsys(CIPHERSIZE,DEC);
    publicShareKey_YaBig = mirvar(0);
    publicShareKey_YbBig = mirvar(0);
    publicShareKey_XaBig = mirvar(0);
    primeNumber_pBig = mirvar(0);
    primitiveRoot_gBig = mirvar(0);
    public_ShareKey_KBig = mirvar(0);
    replaceRandomSeed();
    cinstr(primeNumber_pBig,getPrimeNumber());
	bigbits(160,publicShareKey_XaBig);
	convert(primitiveRoot_g,primitiveRoot_gBig);
	powmod(primitiveRoot_gBig,publicShareKey_XaBig,primeNumber_pBig,publicShareKey_YaBig);
	cotstr(primeNumber_pBig,primeNumber_pStr);
	cotstr(primitiveRoot_gBig,primitiveRoot_gStr);
	cotstr(publicShareKey_YaBig,publicShareKey_YaStr);
	if(sendMsg(client_Socket,primeNumber_pStr) == -1){
		perror("getPulicShareKey_send_primeNumber");
		return -1;
	}
	if(sendMsg(client_Socket,primitiveRoot_gStr) == -1){
		perror("getPublicShareKey_send_primitiveRoot");
		return -1;
	}
	if(sendMsg(client_Socket,publicShareKey_YaStr) == -1){
		perror("getPublicShareKey_send_publicShareKey_YaStr");
		return -1;
	}
	if(recvMsg(client_Socket,publicShareKey_YbStr) == -1){
		perror("getPublicShareKey_recv_publicShareKey_YbStr");
		return -1;
	}
	cinstr(publicShareKey_YbBig,publicShareKey_YbStr);
	powmod(publicShareKey_YbBig,publicShareKey_XaBig,primeNumber_pBig,public_ShareKey_KBig);
	cotstr(public_ShareKey_KBig,public_ShareKey_KStr);
	mirexit();
	return 0;
}

//**************************************************************************
//function name:precomputationPreprocessing()
//in :int mixnode_Typeg,publicShareKey_Xa);
//	  int prior_Socket
//	  int next_Socket
//	  CIPHERTYPE_SHORT groupG_Generator_g
//out:char *processing_Value_RStr[CIPHERSIZE]
//	  char *processing_Value_SStr[CIPHERSIZE]
//	  char *processing_Value_XStr[CIPHERSIZE]
//	  char publicKey_eStr
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.24 Tue 20:19
//Last Edition: 2018.8.29 Wed 14:52
//**************************************************************************
int precomputationPreprocessing(int mixnode_Type,int prior_Socket,int next_Socket,CIPHERTYPE_SHORT groupG_Generator_g,\
		char (*processing_Value_RStr)[CIPHERSIZE],char (*processing_Value_SStr)[CIPHERSIZE],\
		char (*processing_Value_XStr)[CIPHERSIZE],char *publicKey_eStr){
	char prior_cryptoProcessing_Value_RStr[MSGNUM][CIPHERSIZE];
	char prior_cryptoProcessing_Value_gXStr[MSGNUM][CIPHERSIZE];
	char cryptoProcessing_Value_RStr[MSGNUM][CIPHERSIZE];
	char cryptoProcessing_Value_gXStr[MSGNUM][CIPHERSIZE];
	if(setPrecomputationInitialValue(mixnode_Type,prior_Socket,next_Socket,processing_Value_RStr,processing_Value_SStr,\
				processing_Value_XStr) == -1){
		printf("setPrecomputationInitialValue Error!\n");
		return -1;
	}
	if(mixnode_Type != 1){
		if(recvpriorMsg(prior_Socket,prior_cryptoProcessing_Value_RStr) == -1){
	        printf("precomputationPreprocessing_recv_prior_cryptoProcessing_Value_RStr error");
        	return -1;
    	}
	    if(recvpriorMsg(prior_Socket,prior_cryptoProcessing_Value_gXStr) == -1){
        	printf("precomputationPreprocessing_recv_prior_cryptoProcessing_Value_gxStr error");
			return -1;
	    }
	}else{
		for(int i = 0;i < MSGNUM;i++){
			strcpy(prior_cryptoProcessing_Value_RStr[i],"1");
			strcpy(prior_cryptoProcessing_Value_gXStr[i],"1");
		}
	}
	calculateProcessingGX(groupG_Generator_g,processing_Value_XStr,prior_cryptoProcessing_Value_gXStr,cryptoProcessing_Value_gXStr);
	calculateProcessingEncrypto(processing_Value_RStr,processing_Value_XStr,publicKey_eStr,prior_cryptoProcessing_Value_RStr,\
				cryptoProcessing_Value_RStr);
	if(sendnextMsg(next_Socket,cryptoProcessing_Value_RStr) == -1){
        printf("precomputationPreprocessing_send_cryptoProcessing_Value_RStr error\n");
        return -1;
    }
    if(sendnextMsg(next_Socket,cryptoProcessing_Value_gXStr) == -1){
        printf("precomputationPreprocessing_send_cryptoProcessing_Value_gXStr error\n");
        return -1;
    }

	printf("precomputationPreprocessing complete!\n");
	return 0;
}

//**************************************************************************
//function name:setPrecomputationInitialValue()
//in :int mixnode_Type
//	  int prior_Socket
//	  int next_Socket
//out:char (*processing_Value_RStr)[CIPHERSIZE]
//	  char (*processing_Value_SStr)[CIPHERSIZE]
//	  char (*processing_Value_XStr)[CIPHERSIZE]
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.27 Fri 21:20
//last Edition: 2018.8.09 Thu 14:39
//**************************************************************************
int setPrecomputationInitialValue(int mixnode_Type,int prior_Socket,int next_Socket,char (*processing_Value_RStr)[CIPHERSIZE],\
		char (*processing_Value_SStr)[CIPHERSIZE],char (*processing_Value_XStr)[CIPHERSIZE]){
	mirsys(CIPHERSIZE,DEC);
	CIPHERTYPE_BIG processing_Value_RBig;
	CIPHERTYPE_BIG processing_Value_SBig;
	CIPHERTYPE_BIG processing_Value_XBig;
	processing_Value_RBig = mirvar(0);
	processing_Value_SBig = mirvar(0);
	processing_Value_XBig = mirvar(0);
	for(int i = 0;i < MSGNUM;i++){
		replaceRandomSeed();
		bigbits(160,processing_Value_RBig);
		bigbits(160,processing_Value_SBig);
		cotstr(processing_Value_RBig,processing_Value_RStr[i]);
		cotstr(processing_Value_SBig,processing_Value_SStr[i]);
	}
	for(int i = 0;i < (2 * MSGNUM);i++){
		replaceRandomSeed();
		bigbits(160,processing_Value_XBig);
		cotstr(processing_Value_XBig,processing_Value_XStr[i]);
	}
	mirexit();
	return 0;
}
//**************************************************************************
//function name:precomputationMixing()
//in :int prior_Socket
//	  int next_Socket
//	  CIPHERTYPE_SHORT groupG_Generator_g
//	  char publicKey_eStr[CIPHERSIZE]
//	  char (*processing_Value_SStr)[CIPHERSIZE]
//	  char (*processing_Value_XStr)[CIPHERSIZE]
//out:int *Pi_NumberGroup
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.24 Tue 20:20
//Last Edition: 2018.8.28 Tue 16:11
//**************************************************************************
int precomputationMixing(int* Pi_NumberGroup,int prior_Socket,int next_Socket,CIPHERTYPE_SHORT groupG_Generator_g,\
		char publicKey_eStr[CIPHERSIZE],char (*processing_Value_SStr)[CIPHERSIZE],char (*processing_Value_XStr)[CIPHERSIZE]){
	char prior_cryptoMixing_Value_PiRSStr[MSGNUM][CIPHERSIZE];
	char prior_cryptoMixing_Value_gXStr[MSGNUM][CIPHERSIZE];
	char cryptoMixing_Value_PiRSStr[MSGNUM][CIPHERSIZE];
	char cryptoMixing_Value_gXStr[MSGNUM][CIPHERSIZE];
	disorderOrderNumberGroup(Pi_NumberGroup);
	if(recvpriorMsg(prior_Socket,prior_cryptoMixing_Value_PiRSStr) == -1){
        printf("precomputationMixing_recvpriorMsg_cryptoMixing_Value_PiRSStr error");
        return -1;
    }
    if(recvpriorMsg(prior_Socket,prior_cryptoMixing_Value_gXStr) == -1){
        printf("precomputationMixing_recvpriorMsg_cryptoMixing_Value_gXStr error");
        return -1;
    }
	calculateMixingEncrypto(processing_Value_SStr,processing_Value_XStr + MSGNUM,publicKey_eStr,prior_cryptoMixing_Value_PiRSStr,\
			Pi_NumberGroup,cryptoMixing_Value_PiRSStr);
	calculateMixingGX(groupG_Generator_g,processing_Value_XStr + MSGNUM,Pi_NumberGroup,prior_cryptoMixing_Value_gXStr,\
			cryptoMixing_Value_gXStr);
    if(sendnextMsg(next_Socket,cryptoMixing_Value_PiRSStr) == -1){
        printf("precomputationMixing_send_cryptoMixing_Value_PiRSStr error");
        return -1;
    }
    if(sendnextMsg(next_Socket,cryptoMixing_Value_gXStr) == -1){
        printf("precomputationMixing_send_cryptoMixing_Value_gXStr error");
        return -1;
    }
    printf("precomputationMixing complete!\n");
	return 0;
}

//**************************************************************************
//function name:disorderOrderNumberGroup
//in :NULL
//out:int *disorder_NumberGroup
//return:NULL
//author:btlshow
//first Edition:2018.8.2 Thu 15:00
//last Edition: 2018.8.5 Sun 17:16
//**************************************************************************
void disorderOrderNumberGroup(int* disorder_NumberGroup){
	int temp;
	int random;
	for(int i = 0;i < MSGNUM;i++){
		*(disorder_NumberGroup + i) = i;
	}
	for(int i = 0;i < MSGNUM;i++){
		random = createRandomNumber(MSGNUM);
		temp = *(disorder_NumberGroup + i);
		*(disorder_NumberGroup + i) = *(disorder_NumberGroup + random);
		*(disorder_NumberGroup + random) = temp;
	}
}

//**************************************************************************
//function name:precomputationPostprocessing()
//in :int prior_Socket
//	  int next_Socket
//	  int mixnode_Type
//	  CIPHERTYPE_SHORT secret_ShareKey_di
//out:char (*plainText_PiRSStr)[CIPHERSIZE]
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.24 Tue 20:22
//Last Edition: 2018.9.02 Sun 09:28
//**************************************************************************
int precomputationPostprocessing(int prior_Socket,int next_Socket,int mixnode_Type,CIPHERTYPE_SHORT secret_ShareKey_di,\
		char (*plainText_PiRSStr)[CIPHERSIZE]){
	CIPHERTYPE_BIG prior_PlainText_PiRSBig[MSGNUM];
	CIPHERTYPE_BIG prior_PlainText_gXBig[MSGNUM];
	CIPHERTYPE_BIG incomplete_PlainText_PiRSBig[MSGNUM];
	CIPHERTYPE_BIG bignumpow_gXdi_ResultBig[MSGNUM];
	CIPHERTYPE_BIG bignummod_ResultBig[MSGNUM];
	CIPHERTYPE_BIG secret_ShareKey_diBig;
	CIPHERTYPE_BIG primeNumber_pBig;
	char prior_PlainText_PiRSStr[MSGNUM][CIPHERSIZE];
	char prior_PlainText_gXStr[MSGNUM][CIPHERSIZE];
	char bignumpow_gXdi_ResultStr[MSGNUM][CIPHERSIZE];
	char incomplete_PlainText_PiRSStr[MSGNUM][CIPHERSIZE];
	mirsys(CIPHERSIZE,DEC);
	for(int i = 0;i < MSGNUM;i++){
		prior_PlainText_PiRSBig[i] = mirvar(0);
		prior_PlainText_gXBig[i] = mirvar(0);
		incomplete_PlainText_PiRSBig[i] = mirvar(0);
		bignumpow_gXdi_ResultBig[i] = mirvar(0);
		bignummod_ResultBig[i] = mirvar(0);
	}
	secret_ShareKey_diBig = mirvar(0);
	primeNumber_pBig = mirvar(0);
	convert(secret_ShareKey_di,secret_ShareKey_diBig);
	cinstr(primeNumber_pBig,getPrimeNumber());
    if(recvpriorMsg(prior_Socket,prior_PlainText_PiRSStr) == -1){
        printf("precomputationPostprocessing_recvpriorMsg_prior_PlainText_PiRSStr error");
        return -1;
    }
    if(recvpriorMsg(prior_Socket,prior_PlainText_gXStr) == -1){
        printf("precomputationPostprocessing_recvpriorMsg_prior_PlainText_gXStr error");
        return -1;
    }
	for(int i = 0;i < MSGNUM;i++){
        cinstr(prior_PlainText_gXBig[i],prior_PlainText_gXStr[i]);
		cinstr(prior_PlainText_PiRSBig[i],prior_PlainText_PiRSStr[i]);
		powmod(prior_PlainText_gXBig[i],secret_ShareKey_diBig,primeNumber_pBig,bignumpow_gXdi_ResultBig[i]);
		xgcd(bignumpow_gXdi_ResultBig[i],primeNumber_pBig,bignumpow_gXdi_ResultBig[i],bignumpow_gXdi_ResultBig[i],\
				bignumpow_gXdi_ResultBig[i]);
		/*that`s what i made to get inverse
		cotstr(bignumpow_gXdi_ResultBig[i],bignumpow_gXdi_ResultStr[i]);
		if(getInverse(bignumpow_gXdi_ResultStr[i],getPrimeNumber(),bignumpow_gXdi_ResultStr[i]) == -1){
			printf("precomputationPostprocessing_getInverse error!\n");
			return -1;
		}
		cinstr(bignumpow_gXdi_ResultBig[i],bignumpow_gXdi_ResultStr[i]);
		*/
		multiply(bignumpow_gXdi_ResultBig[i],prior_PlainText_PiRSBig[i],incomplete_PlainText_PiRSBig[i]);
		divide(incomplete_PlainText_PiRSBig[i],primeNumber_pBig,bignummod_ResultBig[i]);
		cotstr(incomplete_PlainText_PiRSBig[i],incomplete_PlainText_PiRSStr[i]);
    }
    if(mixnode_Type == 3){
        for(int i = 0;i < MSGNUM;i++){
            strcpy(*(plainText_PiRSStr+i),incomplete_PlainText_PiRSStr[i]);
        }
    }else{
		if(sendnextMsg(next_Socket,incomplete_PlainText_PiRSStr) == -1){
    	    printf("precomputationPostprocessing_sendpriorMsg_incomplete_PlainText_PiRSStr error");
        	return -1;
    	}
	    if(sendnextMsg(next_Socket,prior_PlainText_gXStr) == -1){
    	    printf("precomputationPostprocessing_sendpriorMsg_prior_PlainText_gXStr error");
        	return -1;
	    }
    }
    printf("precomputationPostprocessing complete\n");
    return 0;
}

//**************************************************************************
//function name:realtimeProcessing() 
//in :int prior_Socket
//	  int next_Socket
//	  int *client_Socket
//	  int mixnode_Type
//	  CIPHERTYPE_SHORT groupG_Generator_g
//	  char publicKey_eStr[CIPHERSIZE]
//	  char (*public_ShareKey_KStr)[MSGNUM]
//	  char processing_Value_XStr[MSGNUM][CIPHERSIZE]
//	  char processing_Value_RStr[MSGNUM][CIPHERSIZE]
//out:NULL
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.24 Tue 20:23
//Last Edition: 2018.8.14 Tue 14:01
//**************************************************************************
int realtimeProcessing(int prior_Socket,int next_Socket,int *client_Socket,int mixnode_Type,CIPHERTYPE_SHORT groupG_Generator_g,\
		char publicKey_eStr[CIPHERSIZE],char (*public_ShareKey_KStr)[CIPHERSIZE],char processing_Value_XStr[MSGNUM][CIPHERSIZE],\
		char processing_Value_RStr[MSGNUM][CIPHERSIZE]){
	char prior_realtime_EncryptoMsgStr[MSGNUM][CIPHERSIZE];
	char prior_realtime_Processing_gXStr[MSGNUM][CIPHERSIZE];
	char realtime_EncryptoMsgStr[MSGNUM][CIPHERSIZE];
	char realtime_Processing_gXStr[MSGNUM][CIPHERSIZE];
	if(mixnode_Type == 1){
		if(getClientMsg(client_Socket,prior_realtime_EncryptoMsgStr) == -1){
			printf("realtimeProcessing_getClientMsg!\n");
			return -1;
		}
	}else{
		if(recvpriorMsg(prior_Socket,prior_realtime_EncryptoMsgStr) == -1){
			printf("realtimeProcessing_recvpriorMsg!\n");
			return -1;
		}
	}
	if(realtimeProcessingEncryptoMsg(prior_realtime_EncryptoMsgStr,realtime_EncryptoMsgStr,public_ShareKey_KStr,processing_Value_RStr) == -1){
		printf("realtimeProcessing_EncryptoMsg!\n");
		return -1;
	}
	if(sendnextMsg(next_Socket,realtime_EncryptoMsgStr) == -1){
		printf("realtimeProcessing_sendnextMsg!\n");
		return -1;
	}
	printf("realtimeProcessing complete\n");
	return 0;
}

//**************************************************************************
//function name:realtimeProcessingEncryptoMsg()
//in :char public_ShareKey_KStr[MSGNUM][CIPHERSIZE]
//	  char processing_Value_RStr[MSGNUM][CIPHERSIZE]
//	  char processing_Value_XStr[MSGNUM][CIPHERSIZE]
//	  char publicKey_eStr[CIPHERSIZE]
//	  char (*prior_realtime_EncryptoMsgStr)[CIPHERSIZE]
//out:char (*realtime_EncryptoMsgStr)[CIPHERSIZE]
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.8.04 Sat 14:42
//last Edition: 2018.8.05 Sun 17:25
//**************************************************************************
int realtimeProcessingEncryptoMsg(char (*prior_realtime_EncryptoMsgStr)[CIPHERSIZE],char(*realtime_EncryptoMsgStr)[CIPHERSIZE],\
		char public_ShareKey_KStr[MSGNUM][CIPHERSIZE],char processing_Value_RStr[MSGNUM][CIPHERSIZE]){
	CIPHERTYPE_BIG public_ShareKey_KBig[MSGNUM];
	CIPHERTYPE_BIG processing_Value_RBig[MSGNUM];
	CIPHERTYPE_BIG prior_realtime_EncryptoMsgBig[MSGNUM];
	CIPHERTYPE_BIG bignumdiv_ResultBig[MSGNUM];
	CIPHERTYPE_BIG bignummul_ResultBig[MSGNUM];
	char bignummul_ResultStr[MSGNUM][CIPHERSIZE];
	mirsys(CIPHERSIZE,DEC);
	for(int i = 0;i < MSGNUM;i++){
		prior_realtime_EncryptoMsgBig[i] = mirvar(0);
		processing_Value_RBig[i] = mirvar(0);
		public_ShareKey_KBig[i] = mirvar(0);
		bignumdiv_ResultBig[i] = mirvar(0);
		bignummul_ResultBig[i] = mirvar(0);
	}
	for(int i = 0;i < MSGNUM;i++){
		cinstr(prior_realtime_EncryptoMsgBig[i],prior_realtime_EncryptoMsgStr[i]);
		cinstr(public_ShareKey_KBig[i],public_ShareKey_KStr[i]);
		cinstr(processing_Value_RBig[i],processing_Value_RStr[i]);
		if(divisible(prior_realtime_EncryptoMsgBig[i],public_ShareKey_KBig[i])){
			divide(prior_realtime_EncryptoMsgBig[i],public_ShareKey_KBig[i],bignumdiv_ResultBig[i]);
		}else{
			printf("can not divisible\n");
			return -1;
		}
		multiply(bignumdiv_ResultBig[i],processing_Value_RBig[i],bignummul_ResultBig[i]);
		cotstr(bignummul_ResultBig[i],realtime_EncryptoMsgStr[i]);
	}
	mirexit();
	return 0;
}

//**************************************************************************
//function name:getClientMsg()
//in :int *client_Socket
//out:char client_Msg
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.8.04 Sat 14:26
//last Edition: 2018.8.09 Thu 14:04
//**************************************************************************
int getClientMsg(int *client_Socket,char (*prior_Msg)[CIPHERSIZE]){
	printf("getClientMsg\n");
    for(int i = 0;i < MSGNUM;i++){
        if(recvMsg(client_Socket[i],(prior_Msg[i])) == -1){
            perror("realtimePreocessing_recv_clientMsg error");
            return -1;
        }
    }
	return 0;
}

//**************************************************************************
//function name:acceptClientSocket()
//in :int my_Socket
//out:int *client_Socket
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.8.3 Fri 20:33
//last Edition: 2018.8.9 Thu 10:23
//**************************************************************************
int acceptClientSocket(int my_Socket,int *client_Socket){
	int sockaddr_Size;
    struct sockaddr_in client_Sockaddr[MSGNUM];
	sockaddr_Size = sizeof(struct sockaddr);
	for(int i = 0;i < MSGNUM;i++){
		if((*(client_Socket + i) = accept(my_Socket,(struct sockaddr*)&client_Sockaddr[i],&sockaddr_Size)) == -1){
            perror("acceptWithClient_accept");
            return -1;
        }
		printf("connect to client:%s,port:%d\n",inet_ntoa(client_Sockaddr[i].sin_addr),client_Sockaddr[i].sin_port);
	}
	return 0;
}

//**************************************************************************
//function name:realtimeMixing()
//in :int prior_Socket
//	  int next_Socket
//	  int client_Socket[MSGNUM];
//	  int mixnode_Type
//	  int *Pi_NumberGroup
//	  char publicKey_eStr[CIPHERSIZE]
//	  char processing_Value_XStr[MSGNUM][CIPHERSIZE]
//	  char processing_Value_SStr[MSGNUM][CIPHERSIZE]
//	  char publicKey_eStr[CIPHERSIZE]
//out:NULL
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.7.24 Tue 20:24
//Last Edition: 2018.8.30 Thu 15:48
//**************************************************************************
int realtimeMixing(int prior_Socket,int next_Socket,int client_Socket[MSGNUM],int mixnode_Type,int *Pi_NumberGroup,\
		CIPHERTYPE_SHORT groupG_Generator_g,char publicKey_eStr[CIPHERSIZE],char processing_Value_SStr[MSGNUM][CIPHERSIZE],\
		char processing_Value_XStr[MSGNUM][CIPHERSIZE],char (*plainText_PiRSStr)[CIPHERSIZE]){
	char prior_realtime_EncryptoMsgStr[MSGNUM][CIPHERSIZE];
	char realtime_EncryptoMsgStr[MSGNUM][CIPHERSIZE];
	if(recvpriorMsg(prior_Socket,prior_realtime_EncryptoMsgStr) == -1){
		printf("realtimeMixing_recvpriorMsg\n");
		return -1;
	}
	realtimeMixingEncryptoMsg(Pi_NumberGroup,prior_realtime_EncryptoMsgStr,realtime_EncryptoMsgStr,processing_Value_SStr);
	if(mixnode_Type != 3){
		if(sendnextMsg(next_Socket,realtime_EncryptoMsgStr) == -1){
			printf("realtimeMixing_sendnextMsg!\n");
			return -1;
		}
	}else{
		if(realtimePostprocessing(next_Socket,realtime_EncryptoMsgStr,plainText_PiRSStr) == -1){
			printf("realtimePostprocessing error\n");
			return -1;
		}
		if(sendnextMsg(next_Socket,plainText_PiRSStr) == -1){
			printf("send plainText error\n");
			return -1;
		}
	}
	printf("realtimeMixing complete!\n");
	if(mixnode_Type == 1){
		if(recvpriorMsg(prior_Socket,plainText_PiRSStr) == -1){
			printf("recv plainText error!\n");
			return -1;
		}
		if(sendMsgToClient(plainText_PiRSStr,client_Socket) == -1){
			printf("send Message to client error\n");
			return -1;
		}
		printf("send message complete!\n");
	}
	return 0;
}

//**************************************************************************
//function name:sendMsgToClient()
//in :char plainText_PiRSStr[MSGNUM][CIPHERSIZE]
//	  int client_Socket[MSGNUM]
//out:NULL
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.8.04 Sat 19:50
//last Edition: 2018.8.04 Sat 20:06
//**************************************************************************
int sendMsgToClient(char plainText_PiRSStr[MSGNUM][CIPHERSIZE],int client_Socket[MSGNUM]){
	for(int i = 0;i < MSGNUM;i++){
		ascStrToClientMsg(plainText_PiRSStr[i]);
		if(send(client_Socket[i],plainText_PiRSStr[i],MSGSIZE,0) == -1){
			perror("sendMsgToClient_send_clientMsg");
			return -1;
		}
	}
	return 0;
}

//**************************************************************************
//function name:realtimeMixingEncryptoMsg()
//in :int Pi_NumberGroup[MSGNUM]
//	  char processing_Value_SStr[MSGNUM][CIPHERSIZE]
//	  char (*prior_realtime_EncryptoMsgStr)[MSGNUM]
//out:char (*realtime_EncryptoMsgStr)[MSGNUM]
//return:NULL
//author:btlshow
//first Edition:2018.8. 4 Sat 17:09
//last Edition: 2018.8.31 Fri 11:29
//**************************************************************************
void realtimeMixingEncryptoMsg(int Pi_NumberGroup[MSGNUM],char (*prior_realtime_EncryptoMsgStr)[CIPHERSIZE],\
		char (*realtime_EncryptoMsgStr)[CIPHERSIZE],char processing_Value_SStr[MSGNUM][CIPHERSIZE]){
	CIPHERTYPE_BIG prior_realtime_EncryptoMsgBig[MSGNUM];
    CIPHERTYPE_BIG realtime_EncryptoMsgBig[MSGNUM];
	CIPHERTYPE_BIG processing_Value_SBig[MSGNUM];
	CIPHERTYPE_BIG bignummul_PiMRS_ResultBig[MSGNUM];
	mirsys(CIPHERSIZE,DEC);
	for(int i = 0;i < MSGNUM;i++){
		prior_realtime_EncryptoMsgBig[i] = mirvar(0);
		realtime_EncryptoMsgBig[i] = mirvar(0);
		processing_Value_SBig[i] = mirvar(0);
		bignummul_PiMRS_ResultBig[i] = mirvar(0);
	}
	for(int i = 0;i < MSGNUM;i++){
		cinstr(prior_realtime_EncryptoMsgBig[Pi_NumberGroup[i]],prior_realtime_EncryptoMsgStr[Pi_NumberGroup[i]]);
		cinstr(processing_Value_SBig[i],processing_Value_SStr[i]);
		multiply(prior_realtime_EncryptoMsgBig[Pi_NumberGroup[i]],processing_Value_SBig[i],bignummul_PiMRS_ResultBig[i]);
		cotstr(bignummul_PiMRS_ResultBig[i],realtime_EncryptoMsgStr[i]);
	}
	mirexit();
}
//**************************************************************************
//function name:realtimePostprocessing()
//in :int next_Socket
//	  char *cryptoMessage[CIPHERSIZE]
//	  char *plainText_PiRSStr[CIPHERSIZE]
//out:NULL
//return:success:0  error:-1 
//author:btlshow
//first Edition:2018.8.06 Mon 22:49
//last Edition: 2018.8.07 Tue 15:12
//**************************************************************************
int realtimePostprocessing(int next_Socket,char (*cryptoMessage)[CIPHERSIZE],char (*plainText_PiRSStr)[CIPHERSIZE]){
	char plainText_MessageStr[MSGNUM][CIPHERSIZE];
	CIPHERTYPE_BIG cryptoMessageBig[MSGNUM];
	CIPHERTYPE_BIG plainText_PiRSBig[MSGNUM];
	CIPHERTYPE_BIG plainText_MessageBig[MSGNUM];
	mirsys(CIPHERSIZE,DEC);
	for(int i = 0;i < MSGNUM;i++){
		cryptoMessageBig[i] = mirvar(0);
		plainText_PiRSBig[i] = mirvar(0);
		plainText_MessageBig[i] = mirvar(0);
	}
	for(int i = 0;i < MSGNUM;i++){
		cinstr(cryptoMessageBig[i],cryptoMessage[i]);
		cinstr(plainText_PiRSBig[i],plainText_PiRSStr[i]);
		if(divisible(cryptoMessageBig[i],plainText_PiRSBig[i])){
			divide(cryptoMessageBig[i],plainText_PiRSBig[i],plainText_MessageBig[i]);
		}else{
			printf("can not divisible!\n");
			return -1;
		}
		cotstr(plainText_MessageBig[i],plainText_MessageStr[i]);
	}
	if(sendnextMsg(next_Socket,plainText_MessageStr) == -1){
		perror("realtimePostprocessing_send plainText_MessageStr!");
		return -1;
	}
	mirexit();
	return 0;
}
//**************************************************************************
//function name:calculateEncryptoProcessing()
//in :char (*processing_Value_RStr)[CIPHERSIZE]
//    char (*processing_Value_XStr)[CIPHERSIZE]
//    char publicKey_eStr
//    char prior_cryptoProcessing_ValueStr[MSGNUM][CIPHERSIZE]
//out:char cryptoProcessing_ValueStr[MSGNUM][CIPHERSIZE]
//return:NULL
//author:btlshow
//first Edition:2018.8.1  Wed 15:14
//last Edition: 2018.8.30 Thu 13:26
//**************************************************************************
void calculateProcessingEncrypto(char (*processing_Value_RStr)[CIPHERSIZE],char (*processing_Value_XStr)[CIPHERSIZE],char *publicKey_eStr,\
        char prior_cryptoProcessing_ValueStr[MSGNUM][CIPHERSIZE],char cryptoProcessing_ValueStr[MSGNUM][CIPHERSIZE]){
    CIPHERTYPE_BIG cryptoProcessing_ValueBig[MSGNUM];
    CIPHERTYPE_BIG prior_cryptoProcessing_ValueBig[MSGNUM];
    CIPHERTYPE_BIG incomplete_cryptoProcessing_ValueBig[MSGNUM];
    CIPHERTYPE_BIG bignumpow_eX_ResultBig[MSGNUM];
	CIPHERTYPE_BIG bignummod_ResultBig[MSGNUM];
    CIPHERTYPE_BIG publicKey_eBig;
    CIPHERTYPE_BIG processing_Value_RBig[MSGNUM];
    CIPHERTYPE_BIG processing_Value_XBig[MSGNUM];
    CIPHERTYPE_BIG primeNumber_pBig;
    mirsys(CIPHERSIZE,DEC);
    for(int i = 0;i < MSGNUM;i++){
        processing_Value_RBig[i] = mirvar(0);
        processing_Value_XBig[i] = mirvar(0);
        cryptoProcessing_ValueBig[i] = mirvar(0);
        prior_cryptoProcessing_ValueBig[i] = mirvar(0);
        incomplete_cryptoProcessing_ValueBig[i] = mirvar(0);
        bignumpow_eX_ResultBig[i] = mirvar(0);
		bignummod_ResultBig[i] = mirvar(0);
    }
    primeNumber_pBig = mirvar(0);
    publicKey_eBig = mirvar(0);
    cinstr(primeNumber_pBig,getPrimeNumber());
    cinstr(publicKey_eBig,publicKey_eStr);
    for(int i = 0;i < MSGNUM;i++){
        cinstr(processing_Value_XBig[i],processing_Value_XStr[i]);
        cinstr(processing_Value_RBig[i],processing_Value_RStr[i]);
        cinstr(prior_cryptoProcessing_ValueBig[i],prior_cryptoProcessing_ValueStr[i]);
        powmod(publicKey_eBig,processing_Value_XBig[i],primeNumber_pBig,bignumpow_eX_ResultBig[i]);
        multiply(bignumpow_eX_ResultBig[i],processing_Value_RBig[i],incomplete_cryptoProcessing_ValueBig[i]);
        multiply(prior_cryptoProcessing_ValueBig[i],incomplete_cryptoProcessing_ValueBig[i],cryptoProcessing_ValueBig[i]);
		divide(cryptoProcessing_ValueBig[i],primeNumber_pBig,bignummod_ResultBig[i]);
		cotstr(cryptoProcessing_ValueBig[i],cryptoProcessing_ValueStr[i]);
    }
    mirexit();
}
//**************************************************************************
//function name:calculateMixingEncrypto()
//in :char (*processing_Value_SStr)[CIPHERSIZE]
//    char (*processing_Value_XStr)[CIPHERSIZE]
//    char publicKey_eStr
//    char prior_cryptoMixing_ValueStr[MSGNUM][CIPHERSIZE]
//    int Pi_NumberGroup[MSGNUM]
//out:char (*cryptoMixing_ValueStr)[CIPHERSIZE]
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.8.29 Wed 14:57
//last Edition: 2018.8.30 Thu 16:15
//**************************************************************************
void calculateMixingEncrypto(char (*processing_Value_SStr)[CIPHERSIZE],char (*processing_Value_XStr)[CIPHERSIZE],\
		char publicKey_eStr[CIPHERSIZE],char prior_cryptoMixing_ValueStr[MSGNUM][CIPHERSIZE],int Pi_NumberGroup[MSGNUM],\
		char (*cryptoMixing_ValueStr)[CIPHERSIZE]){
    CIPHERTYPE_BIG processing_Value_SBig[MSGNUM];
    CIPHERTYPE_BIG processing_Value_XBig[MSGNUM];
    CIPHERTYPE_BIG prior_cryptoMixing_ValueBig[MSGNUM];
	CIPHERTYPE_BIG incomplete_cryptoMixing_ValueBig[MSGNUM];
    CIPHERTYPE_BIG cryptoMixing_ValueBig[MSGNUM];
    CIPHERTYPE_BIG bignumpow_eX_ResultBig[MSGNUM];
	CIPHERTYPE_BIG bignummod_ResultBig[MSGNUM];
    CIPHERTYPE_BIG publicKey_eBig;
    CIPHERTYPE_BIG primeNumber_pBig;
    mirsys(CIPHERSIZE,DEC);
    for(int i = 0;i < MSGNUM;i++){
        processing_Value_SBig[i] = mirvar(0);
        processing_Value_XBig[i] = mirvar(0);
        prior_cryptoMixing_ValueBig[i] = mirvar(0);
		incomplete_cryptoMixing_ValueBig[i] = mirvar(0);
        cryptoMixing_ValueBig[i] = mirvar(0);
        bignumpow_eX_ResultBig[i] = mirvar(0);
		bignummod_ResultBig[i] = mirvar(0);
    }
    publicKey_eBig = mirvar(0);
    primeNumber_pBig = mirvar(0);
    for(int i = 0;i < MSGNUM;i++){
        cinstr(processing_Value_SBig[i],processing_Value_SStr[i]);
        cinstr(processing_Value_XBig[i],processing_Value_XStr[i]);
        cinstr(prior_cryptoMixing_ValueBig[i],prior_cryptoMixing_ValueStr[i]);
    }
    cinstr(publicKey_eBig,publicKey_eStr);
    cinstr(primeNumber_pBig,getPrimeNumber());
    for(int i = 0;i < MSGNUM;i++){
        powmod(publicKey_eBig,processing_Value_XBig[i],primeNumber_pBig,bignumpow_eX_ResultBig[i]);
        multiply(bignumpow_eX_ResultBig[i],processing_Value_SBig[i],incomplete_cryptoMixing_ValueBig[i]);
        multiply(incomplete_cryptoMixing_ValueBig[i],prior_cryptoMixing_ValueBig[Pi_NumberGroup[i]],cryptoMixing_ValueBig[i]);
		divide(cryptoMixing_ValueBig[i],primeNumber_pBig,bignummod_ResultBig[i]);
		cotstr(cryptoMixing_ValueBig[i],cryptoMixing_ValueStr[i]);
	}
    mirexit();
}
//**************************************************************************
//function name:calculateProcessingGX()
//in :CIPHERTYPE_SHORT groupG_Generator_g
//	  char processing_Value_XStr[MSGNUM][CIPHERSIZE]
//	  char prior_GXStr[MSGNUM][CIPHERSIZE]
//out:char result_GXStr[MSGNUM][CIPHERSIZE]
//return:NULL
//first Edition:2018.8.28 Tue 20:24
//last Edition: 2018.8.28 Tue 20:24
//**************************************************************************
void calculateProcessingGX(CIPHERTYPE_SHORT groupG_Generator_g,char processing_Value_XStr[MSGNUM][CIPHERSIZE],\
		char prior_gXStr[MSGNUM][CIPHERSIZE],char (*result_gXStr)[CIPHERSIZE]){
	CIPHERTYPE_BIG groupG_Generator_gBig;
	CIPHERTYPE_BIG primeNumber_pBig;
	CIPHERTYPE_BIG processing_Value_XBig[MSGNUM];
	CIPHERTYPE_BIG prior_gXBig[MSGNUM];
	CIPHERTYPE_BIG incomplete_gXBig[MSGNUM];
	CIPHERTYPE_BIG result_gXBig[MSGNUM];
	CIPHERTYPE_BIG bignummod_ResultBig[MSGNUM];
	mirsys(CIPHERSIZE,DEC);
	for(int i = 0;i < MSGNUM;i++){
		processing_Value_XBig[i] = mirvar(0);
		prior_gXBig[i] = mirvar(0);
		incomplete_gXBig[i] = mirvar(0);
		result_gXBig[i] = mirvar(0);
		bignummod_ResultBig[i] = mirvar(0);
	}
	groupG_Generator_gBig = mirvar(0);
	primeNumber_pBig = mirvar(0);
	convert(groupG_Generator_g,groupG_Generator_gBig);
	cinstr(primeNumber_pBig,getPrimeNumber());
	for(int i = 0;i < MSGNUM;i++){
		cinstr(processing_Value_XBig[i],processing_Value_XStr[i]);
		cinstr(prior_gXBig[i],prior_gXStr[i]);
		powmod(groupG_Generator_gBig,processing_Value_XBig[i],primeNumber_pBig,incomplete_gXBig[i]);
		multiply(incomplete_gXBig[i],prior_gXBig[i],result_gXBig[i]);
		divide(result_gXBig[i],primeNumber_pBig,bignummod_ResultBig[i]);
		cotstr(result_gXBig[i],result_gXStr[i]);
	}
	mirexit();
}
//**************************************************************************
//function name:calculateMixingGX()
//in :CIPHERTYPE_SHORT groupG_Generator_g
//	  int Pi_NumberGroup[MSGNUM]
//    char processing_Value_XStr[MSGNUM][CIPHERSIZE]
//    char prior_GXStr[MSGNUM][CIPHERSIZE]
//out:char result_GXStr[MSGNUM][CIPHERSIZE]
//return:NULL
//first Edition:2018.8.28 Tue 20:24
//last Edition: 2018.8.28 Tue 20:24
//**************************************************************************
void calculateMixingGX(CIPHERTYPE_SHORT groupG_Generator_g,char processing_Value_XStr[MSGNUM][CIPHERSIZE],int Pi_NumberGroup[MSGNUM],\
        char prior_gXStr[MSGNUM][CIPHERSIZE],char (*result_gXStr)[CIPHERSIZE]){
    CIPHERTYPE_BIG groupG_Generator_gBig;
    CIPHERTYPE_BIG primeNumber_pBig;
    CIPHERTYPE_BIG processing_Value_XBig[MSGNUM];
    CIPHERTYPE_BIG prior_gXBig[MSGNUM];
    CIPHERTYPE_BIG incomplete_gXBig[MSGNUM];
    CIPHERTYPE_BIG result_gXBig[MSGNUM];
	CIPHERTYPE_BIG bignummod_ResultBig[MSGNUM];
    mirsys(CIPHERSIZE,DEC);
    for(int i = 0;i < MSGNUM;i++){
        processing_Value_XBig[i] = mirvar(0);
        prior_gXBig[i] = mirvar(0);
        incomplete_gXBig[i] = mirvar(0);
        result_gXBig[i] = mirvar(0);
		bignummod_ResultBig[i] = mirvar(0);
    }
    groupG_Generator_gBig = mirvar(0);
    primeNumber_pBig = mirvar(0);
    convert(groupG_Generator_g,groupG_Generator_gBig);
    cinstr(primeNumber_pBig,getPrimeNumber());
    for(int i = 0;i < MSGNUM;i++){
        cinstr(processing_Value_XBig[i],processing_Value_XStr[i]);
        cinstr(prior_gXBig[Pi_NumberGroup[i]],prior_gXStr[Pi_NumberGroup[i]]);
        powmod(groupG_Generator_gBig,processing_Value_XBig[i],primeNumber_pBig,incomplete_gXBig[i]);
        multiply(incomplete_gXBig[i],prior_gXBig[Pi_NumberGroup[i]],result_gXBig[i]);
		divide(result_gXBig[i],primeNumber_pBig,bignummod_ResultBig[i]);
        cotstr(result_gXBig[i],result_gXStr[i]);
    }
    mirexit();
}
//**************************************************************************
//function name:getInverse()
//in :char orignNumberStr[CIPHERSIZE]
//	  char primeNumberStr[CIPHERSIZE]
//out:char* inverseNumbverStr
//return:success:0 error:-1
//author:btlshow
//first Edition:2018.9.03 Mon 14:07
//last Edition: 2018.9.03 Mon 21:10
//**************************************************************************
int getInverse(char orignNumberStr[CIPHERSIZE],char primeNumberStr[CIPHERSIZE],char* inverseNumberStr){
    CIPHERTYPE_BIG dBig;
    CIPHERTYPE_BIG xBig;
    CIPHERTYPE_BIG yBig;
    CIPHERTYPE_BIG orignNumberBig;
    CIPHERTYPE_BIG primeNumberBig;
    CIPHERTYPE_BIG bignummod_ResultBig;
    CIPHERTYPE_BIG bignumadd_ResultBig;
    char dStr[CIPHERSIZE];
    char xStr[CIPHERSIZE];
    char yStr[CIPHERSIZE];
    dBig = mirvar(0);
    xBig = mirvar(0);
    yBig = mirvar(0);
    orignNumberBig = mirvar(0);
    primeNumberBig = mirvar(0);
    bignummod_ResultBig = mirvar(0);
    bignumadd_ResultBig = mirvar(0);
    extGcd(orignNumberStr,primeNumberStr,dStr,xStr,yStr);
    cinstr(primeNumberBig,primeNumberStr);
    cinstr(xBig,xStr);
    if(strcmp(dStr,"1")){
        add(xBig,primeNumberBig,bignumadd_ResultBig);
        divide(bignumadd_ResultBig,primeNumberBig,bignummod_ResultBig);
        cotstr(bignumadd_ResultBig,inverseNumberStr);
		printf("success!\n");
        return 0;
    }else{
        strcpy("1",inverseNumberStr);
        return -1;
    }
}

//**************************************************************************
//function name:extGcd()
//in :char orignNumberStr[CIPHERSIZE]
//    char primeNumberStr[CIPHERSIZE]
//out:char* dStr
//	  char* xStr
//	  char* yStr
//return:NULL
//author:btlshow
//first Edition:2018.9.03 Mon 14:07
//last Edition: 2018.9.03 Mon 21:14
//**************************************************************************
void extGcd(char orignNumberStr[CIPHERSIZE],char primeNumberStr[CIPHERSIZE],char* dStr,char* xStr,char* yStr){
    CIPHERTYPE_BIG orignNumberBig;
    CIPHERTYPE_BIG orignNumberBig2;
    CIPHERTYPE_BIG primeNumberBig;
    CIPHERTYPE_BIG dBig;
    CIPHERTYPE_BIG xBig;
    CIPHERTYPE_BIG yBig;
    CIPHERTYPE_BIG bignumdiv_ResultBig;
    CIPHERTYPE_BIG bignummul_ResultBig;
    CIPHERTYPE_BIG bignumsub_ResultBig;
    char orignNumberStr2[CIPHERSIZE];
    orignNumberBig = mirvar(0);
    orignNumberBig2 = mirvar(0);
    primeNumberBig = mirvar(0);
    dBig = mirvar(0);
    xBig = mirvar(0);
    yBig = mirvar(0);
    bignumdiv_ResultBig = mirvar(0);
    bignummul_ResultBig = mirvar(0);
    bignumsub_ResultBig = mirvar(0);
    cinstr(orignNumberBig,orignNumberStr);
    cinstr(orignNumberBig2,orignNumberStr);
    cinstr(primeNumberBig,primeNumberStr);
    if(!strcmp(primeNumberStr,"0")){
        copy(orignNumberBig,dBig);
        convert(1,xBig);
        convert(0,yBig);
        cotstr(xBig,xStr);
        cotstr(yBig,yStr);
    }else{
        divide(orignNumberBig2,primeNumberBig,bignumdiv_ResultBig);
        cotstr(orignNumberBig2,orignNumberStr2);
        extGcd(primeNumberStr,orignNumberStr2,dStr,yStr,xStr);
        cinstr(xBig,xStr);
        cinstr(yBig,yStr);
        multiply(xBig,bignumdiv_ResultBig,bignummul_ResultBig);
        subtract(yBig,bignummul_ResultBig,bignumsub_ResultBig);
        copy(bignumsub_ResultBig,yBig);
        cotstr(yBig,yStr);
    }
}

//**************************************************************************
//function name:createRandomNumber()
//in :NULL
//out:NULL
//return:int randomNum
//author:btlshow
//first Edition:2018.7.26 Thu 19.10
//Last Edition: 2018.8.12 Sun 19.40
//**************************************************************************
int createRandomNumber(int randomRange){
	mirsys(CIPHERSIZE,DEC);
	replaceRandomSeed();
    int original_Num = brand() % randomRange;
    if((original_Num < 10)&&(randomRange >= 50)){
    	return createRandomNumber(randomRange);
    }else{
    	return original_Num;
    }
}

//**************************************************************************
//function name:createRandomPrimeNumber()
//in :NULL
//out:NULL
//return:int randomPrimeNum
//author:btlshow
//first Edition:2018.7.26 Thu 19.10
//Last Edition: 2018.7.28 Sat 16.17
//**************************************************************************
char* getPrimeNumber(){
	char *primetext=
	"155315526351482395991155996351231807220169644828378937433223838972232518351958838087073321845624756550146945246003790108045940383194773439496051917019892370102341378990113959561895891019716873290512815434724157588460613638202017020672756091067223336194394910765309830876066246480156617492164140095427773547319";
	return primetext;
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
	int *p;
    p = (int*)malloc(sizeof(int));
    irand((unsigned long)p);
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
	char msg_Str[MSGSIZE];
	char singlechar_ASCStr[3];
	int singlechar_ASC;
    strcpy(msg_Str,client_Msg);
	for(int i = 0;i < strlen(msg_Str);i++){
		singlechar_ASC = msg_Str[i];
		sprintf(singlechar_ASCStr,"%d",singlechar_ASC);
		for(int j = 0;j < 3 - strlen(singlechar_ASCStr);j++){
			singlechar_ASCStr[2] = singlechar_ASCStr[1];
			singlechar_ASCStr[1] = singlechar_ASCStr[0];
			singlechar_ASCStr[0] = '0';
		}
		for(int j = 0;j < 3;j++){
			*(client_Msg + 3 * i +j) = *(singlechar_ASCStr + j);		
		}
	}
	*(client_Msg + strlen(msg_Str) + 1)='\0';
}

//**************************************************************************
//function name:ascStrToClientMsg()
//in :NULL
//out:char *ascStr
//return:success:0  error:-1
//author:btlshow
//first Edition:2018.8.4 Sat 22:40
//last Edition: 2018.8.4 Sat 22:40
//**************************************************************************
int ascStrToClientMsg(char *ascStr){
	char asc_CharStr[CIPHERSIZE];
	char singlechar_ASCStr[4];
	int i;
	cutStr(ascStr,asc_CharStr,CIPHERSIZE,1);
	if((strlen(asc_CharStr) % 3) != 0){
		printf("ascStrToClientMsg_strlen(asc_Char) %% 3 != 0!\n");
		return -1;
	}
	for(i = 0;i < (strlen(asc_CharStr) / 3);i++){
		for(int j = 0;j < 3;j++){
			singlechar_ASCStr[j] = asc_CharStr[3 * i + j];
		}
		singlechar_ASCStr[3] = '\0';
		int char_Num = atoi(singlechar_ASCStr);
		if(char_Num > 255){
			printf("acsStrToClientMsg_char_Num > 255!\n");
			return -1;
		}
		*(ascStr + i) = char_Num;
	}
	*(ascStr + i) = '\0';
	return 0;
}
