//////////////////////////////////////////////////////////////////////////////////////////////////
// File Name		: proxy_cache.c								//
// Date			: 2022/06/08								//
// Os			: Ubuntu 16.04 LTS 64bits						//
// Author		: Ha Ju Yeong								//
// Student ID		: 2019202100								//
// ---------------------------------------------------------------------------------------------//
// Title : System Programming Assignment #3-2(proxy server)					//
// Description : 1. Create thread thread function.				 		//
//		3. Write Logfile in thread function.						// 
//////////////////////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>	//SHA1
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>		//mkdir
#include <sys/stat.h>		//mkdir
#include <fcntl.h>		//creat
#include <dirent.h>		//DIR*, opendir ..
#include <time.h>		//time, localtime, difftime 
#include <wait.h>		//waitpid
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>		//gethostbyname
#include <sys/sem.h>
#include <sys/ipc.h>
#include <pthread.h>
#define BUFFSIZE	1024
#define PORTNO		39999

int sub;			//sub prcess count
time_t Start, End;		//process start, end time
char *getHomeDir(char *home);
char *sha1_hash(char *input_url, char *hashed_url);
int IsHit(char *cache_path, char *d_name, char *f_name);

void p(int semid); 
void v(int semid); 
void *thr_fn(void* buf);

//////////////////////////////////////////////////////////////////////////////////////////
// handler										//
// =====================================================================================//
// Purpose : To wait for any child process.						//
//////////////////////////////////////////////////////////////////////////////////////////
static void handler() 
{
	pid_t pid;
	int status;
	while((pid = waitpid(-1, &status, WNOHANG))>0);
}
//////////////////////////////////////////////////////////////////////////////////////////
// sig_alrm										//
// ==================================================================================== //
// Purpose : To print "No reponse" and terminate chlid process				//
//////////////////////////////////////////////////////////////////////////////////////////
void sig_alrm()
{
	printf("=======   No Response  =======\n");
	
	alarm(0);
	kill(getpid() , SIGKILL);
	
}
//////////////////////////////////////////////////////////////////////////////////////////
// getIPAddr										//
// =====================================================================================//
// Input : char* -> host name(domain name) 						//
// Output : char* -> host ip(IPv4 address)						//
// Purpose : Text-URL ->dotted IPv4 address						//
//////////////////////////////////////////////////////////////////////////////////////////
char *getIPAddr(char *addr)
{
	struct hostent* hent;
	char* haddr;
	int len = strlen(addr);
		
	if( (hent = (struct hostent*)gethostbyname(addr)) != NULL) {
		haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));
	}
	return haddr;
}

//////////////////////////////////////////////////////////////////////////////////////////
// sig_int										//
// =====================================================================================//
// Purpose : SIG_INT handler when typing ctrl+c						//
//////////////////////////////////////////////////////////////////////////////////////////
void sig_int()
{
	//Find logfile.txt path
	char log_path[255];
	getHomeDir(log_path);
	strcat(log_path, "/logfile/logfile.txt");
	
	//Open logfile
	FILE *log = fopen(log_path, "a");
	if(log == NULL) {
		printf("[error]logfile open\n");
		exit(1);
	}

	time(&End);	//End time when terminated
	
	//Write logfile
	fprintf(log,"**SERVER**[Terminated] run time : %.0lf sec. #sub process: %d\n",difftime(End, Start),sub);
	
	fclose(log);
	exit(0);
}

//thr_fn variable
pid_t pid;
struct tm *ltp;
char d_name[5];
char f_name[256];
char url[256];

//log structure (not using)
struct MyStruct{
	pid_t pid;
	char d_name[5];
	char f_name[256];
	char url[256];
}my;

//////////////////////////////////////////////////////////////////////////////////////////
// thr_fn										//
// =====================================================================================//
// Input : void* -> Hit or Miss								//
// Purpose : Performs thread funtion writing Logfile.					//
//////////////////////////////////////////////////////////////////////////////////////////
void *thr_fn(void* buf)
{
	printf("*PID# %d create the *TID# %ld\n", getpid(),pthread_self());
	//Find logfile.txt path
	char log_path[255];
	getHomeDir(log_path);
	strcat(log_path, "/logfile/logfile.txt");
	
	//Open logfile
	FILE *log = fopen(log_path, "a");
	if(log == NULL) {
		printf("[error]logfile open\n");
		exit(1);
	}

	//Write logfile
	if(strcmp(buf,"HIT")==0) {
		fprintf(log, "[%s]%s/%s ", (char*)buf,d_name, f_name);
		fprintf(log, "-[%04d/%02d/%02d, %02d:%02d:%02d]\n",ltp->tm_year+1900, ltp->tm_mon+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);
		fprintf(log, "[%s]%s\n", (char*)buf,url);
	}
	else if (strcmp(buf,"MISS") == 0) {
		fprintf(log,"[%s]%s ", (char*)buf,url);
		fprintf(log, "-[%04d/%02d/%02d, %02d:%02d:%02d]\n",ltp->tm_year+1900, ltp->tm_mon+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);

	}
		
	printf("*TID# %ld is exited.\n",pthread_self());
	
	fclose(log);
}
int main()
{
	//Startup program
	time(&Start);
	time_t start, end;				//connect time				
	//char url[256];
	char hashed_url[256];
	char home[256];
	char cache_path[256];
	//char d_name[5];
	char d_path[256];
	//char f_name[256];
	char f_path[256];
	char log_path[256];
	char command[256];				//CMD

	time_t url_time;
	//struct tm *ltp;
	int hit = 0, miss =0;				//hit miss count
	//pid_t pid;
	int status;

	int state;

	umask(0);
	getHomeDir(home);				//home path
	
	strcpy(cache_path, home);			//home/~
	strcat(cache_path, "/cache/");
	mkdir(cache_path, 0777);				//home/cache/~
	
	strcpy(log_path, home);
	strcat(log_path, "/logfile/");			//home/logfile/~
	mkdir(log_path, 0777);
	strcat(log_path, "logfile.txt");
	/*FILE *log =fopen(log_path, "a");				//logfile open
	if(log == NULL) {
		printf("[error]logfile open\n");
		return 1;
	}*/
	
	struct sockaddr_in server_addr, client_addr;
	int socket_fd, client_fd;
	int len, len_out;

	if( (socket_fd = socket(PF_INET, SOCK_STREAM, 0) )<0) {	//socket
		printf("Server: Can't open stream socket.\n");
		return 0;
	}

	bzero((char*)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(PORTNO);

	int opt = 1;
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if(bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr))<0) {	//bind
		printf("Server: Can't bind local address.\n");
		return 0;
	}

	listen(socket_fd, 5);	//5 client available
	signal(SIGCHLD,(void *)handler);	//SIGCHLD
	signal(SIGALRM,(void *)sig_alrm);	//SIGALRM
	signal(SIGINT, (void *)sig_int);	//SIGINT

	//semaphore
	int semid;  
	union semun{ 
		int val;
		struct semid_ds *buf;
		unsigned short int *array;
	}arg;
	//sempget
	if((semid = semget((key_t)PORTNO,1, IPC_CREAT|0666))==-1){
		perror("semget failed");
		exit(1);
	}

	arg.val = 1;
	//semctl
	if((semctl(semid, 0 ,SETVAL,arg))==-1){
		perror("sectil failed");
		exit(1);
	}

	while(1) 
	{	
		struct in_addr inet_client_address;
		char buf[BUFFSIZE];

		char response_header[BUFFSIZE] = {0,};	//response_header
		char response_message[BUFFSIZE] = {0,}; //response_message

		char tmp[BUFFSIZE] = {0,};
		char method[20] = {0,};
		//char url[BUFFSIZE] = {0,};

		char *tok = NULL;

		char buf2[BUFFSIZE];
		bzero((char*)&client_addr, sizeof(client_addr));
		len = sizeof(client_addr);
		client_fd = accept(socket_fd,(struct sockaddr *)&client_addr, &len);	//accept
		if(client_fd <0 ) {
			printf("Server : accept failed.\n");
			return 0;
		}
		
	
		inet_client_address.s_addr = client_addr.sin_addr.s_addr;
		/*printf("[%s:%d] client was connected.\n", 
			inet_ntoa(inet_client_address), client_addr.sin_port);*/

		//Create sub process
		pid = fork();	
		sub++;
		if(pid ==-1) {
			
			close(client_fd);
			close(socket_fd);
			continue;
		}
		//Child process Code
		else if (pid == 0)	
		{	
			
			time(&start);
			//Receive request message
			if(read(client_fd, buf, BUFFSIZE)<0) continue; 
 			//Set alarm 
			//alarm(15);	

			//Print request message
			strcpy(buf2, buf);
			strcpy(tmp, buf);
			/*puts("==============================");	//print request message
			printf("Resquest from [%s : %d]\n", inet_ntoa(inet_client_address), client_addr.sin_port);
			puts(buf);
			puts("==============================\n");
			*/
			tok = strtok(tmp, " ");
			strcpy(method, tok);

			if(strcmp(method, "GET") == 0) {	//get: method(including url)
				tok = strtok(NULL, " ");		
				strcpy(url, tok);
			}
			
			//Get Host name
			tok = strtok(NULL, "\n");
			char *tok2 = strtok(NULL, " ");
			
			char method2[20] = {0, };
			strcpy(method2, tok2);
		
			char host[20] = {0,};
			if(strcmp(method2, "Host:") == 0) {
				tok2 = strtok(NULL, "\n");
				strcpy(host, tok2);
			}	
			host[strlen(host)-1] = '\0';

			//Get url(for hashing url)
			char temp[255];
			sscanf(url, "http://%s/", url);
			if(url[strlen(url)-1] == '/') {
				url[strlen(url)-1] = '\0';
			}
			
			//printf("host name: %s\n", host);
	
			//GET HOST IP 
			char* IPAddr;
			IPAddr = getIPAddr(host);
			
			char ip[255];
			strcpy(ip, IPAddr);
			//printf("Host IP:%s\n", ip);		
			
			//Get url time
			time(&url_time);
			ltp = localtime(&url_time);		
			
			sha1_hash(url, hashed_url);		//SHA

			
			strncpy(d_name, hashed_url, 3);		//dir name	
			d_name[3] = '\0';
					
			strcpy(d_path, cache_path);
			strcat(d_path, d_name);			//dir path

			for(int i = 3; i < strlen(hashed_url)+1; i++){	//file name
				f_name[i-3] = hashed_url[i];
			}
			
			//thread variable
			int err;
			void *tret;
			pthread_t tid;

			//Hit
			if(IsHit(cache_path, d_name, f_name))
			{
				//Get cache file
				strcat(d_path, f_name);
				strcpy(f_path, d_path);
				//GET request message from cache file
				char temp[BUFFSIZE] = {0,};
				int fd;
				fd = open(f_path, O_WRONLY);
				read(fd, buf2,sizeof(buf2));
				//strcpy(buf2, temp);
				close(fd);
												
				//HIT logfile
				p(semid);
				strcpy(buf, "HIT");
				buf[3] = '\0';
				hit++;

				//create pthread
				err = pthread_create(&tid, NULL, thr_fn,(void*)buf);
				
				if(err != 0) {
					printf("pthread_create() error.\n");
					return 0;
				}
				
				pthread_join(tid,&tret);
				v(semid);

				
			}
			//MISS
			else 
			{
				//MISS logfile
				p(semid);
				strcpy(buf, "MISS");
				buf[4] = '\0';	
				miss++;
				
				//create pthread
				err = pthread_create(&tid,NULL,thr_fn,(void*)buf);
		
				if(err != 0) {
					printf("phtread_create() error.\n");
					return 0;
				}
				
				//fprintf(log, "[Miss] ServerPID : %d | %s", getpid(),url);
				//fprintf(log, "-[%04d/%02d/%02d, %02d:%02d:%02d]\n",ltp->tm_year+1900, ltp->tm_mon+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);
				pthread_join(tid,&tret);
				v(semid);	

				mkdir(d_path, 0777);			//make dir

				strcpy(f_path, d_path);
				strcat(f_path, "/");
				strcat(f_path, f_name);			//file path
 
				//Save request message in cache file	
				int fd;
				fd = open(f_path, O_WRONLY | O_TRUNC | O_CREAT, 0644);		//make file
				if(fd == -1)				//creat error
				{
					printf("[error] creat \n");
					return 1;
				}
				write(fd, buf2 ,strlen(buf2));	
				close(fd);

			}//endelse (miss)
			len_out = strlen(buf);
			/*
			sprintf(response_message, 
				"<h1>%s</h1><br>"
				"%s:%d<br>"
				"%s<br>"
				"kw2019202100", buf,inet_ntoa(inet_client_address), client_addr.sin_port, url);
			sprintf(response_header, 
				"HTTP/1.0 200 OK\r\n"
				"Server:2018 simple web server\r\n"
				"Content-length:%lu\r\n"
				"Content-type:text/html\r\n\r\n", strlen(response_message));
			*/
			//sleep(10);
						
			//write(client_fd, response_header, strlen(response_header));	//send response message(header+body) to web browser
			//write(client_fd, response_message, strlen(response_message));




			//Send response message to Web browser
			write(client_fd, buf2, strlen(buf2));
		//	alarm(0);	//disable alarm

			bzero(buf, sizeof(buf));
				
			time(&end);
			
			//fprintf(log, "[Terminated] ServerPID : %d | run time: %.0lf sec. #request hit : %d, miss : %d\n", getpid(),difftime(end, start), hit, miss);
			//after client was exited
			/*printf("[%s:%d] client was disconnected.\n", 
					inet_ntoa(inet_client_address), client_addr.sin_port);*/
			close(client_fd);
		
			exit(0);
		}	//endelseif (child process)
		else {
			close(client_fd);
		}
		
	}//endwhile (accept)

	//fclose(log);	//logfile close
	close(socket_fd);
	return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////
// getHomeDir										//
// =====================================================================================//
// Input : char* -> empty								//
// Output : char* -> home directory path						//
// Purpose : Extract home directory path						//
//////////////////////////////////////////////////////////////////////////////////////////
char *getHomeDir(char *home)
{
	struct passwd *usr_info = getpwuid( getuid() );
	strcpy(home, usr_info -> pw_dir);

	return home;
}

//////////////////////////////////////////////////////////////////////////////////////////
// sha1_hash										//
// =====================================================================================//
// Input : char* -> empty								//
// Input : char* -> empty								//
// Ouput : char* -> hashed url 								//
// Purpose : change url to hashed url							//
//////////////////////////////////////////////////////////////////////////////////////////
char *sha1_hash(char *input_url, char *hashed_url) {
	unsigned char hashed_160bits[20];
	char hashed_hex[41];
	int i;

	SHA1(input_url, strlen(input_url), hashed_160bits);		

	for(int i = 0; i < sizeof(hashed_160bits); i++)
		sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);
	
	strcpy(hashed_url, hashed_hex);

	return hashed_url;
}

//////////////////////////////////////////////////////////////////////////////////////////
// IsHit										//
// =====================================================================================//
// Input : char * -> ~/cache/ path							//
// Input : char * -> hashed directory directory	name					//	// Input : char * -> hashed directory file name						//
// Output : Int	-> 1 hit								//
// 		   2 miss								//
// Purpose : Check the cache directory to determine if it is a hit or a miss		//
//////////////////////////////////////////////////////////////////////////////////////////
int IsHit(char *cache_path, char *d_name, char *f_name)
{
	char dir[256];
	strcpy(dir, cache_path);
	strcat(dir, d_name);

	struct dirent *pFile;
	DIR *pDir;
	
	pDir = opendir(dir);
	if(pDir == NULL ) {	//[error] open dir(miss)
		return 0;
	}
	for(pFile = readdir(pDir); pFile; pFile = readdir(pDir)) {	//Is Directory
		if( strcmp(pFile -> d_name, f_name ) == 0) 
			return 1;
	}
	closedir(pDir);
	
	return 0;	//No Directory
}
void p(int semid){
	printf("*PID# %d is waiting the semaphore.\n", getpid());
	struct sembuf pbuf;
	pbuf.sem_num=0;
	pbuf.sem_op =-1;
	pbuf.sem_flg = SEM_UNDO;
	if((semop(semid, &pbuf, 1 )) == -1){
		perror(" p : semop Failed");
		exit(1);
	}
	printf("*PID# %d is in the critical zone.\n", getpid());
//	sleep(1);
}

void v(int semid){
	struct sembuf vbuf;
	vbuf.sem_num=0;
	vbuf.sem_op = 1;
	vbuf.sem_flg = SEM_UNDO;
	if((semop(semid, &vbuf , 1))==-1){
		perror(" v : semop failed");
		exit(1);
	}
	printf("PID# %d exited the critical zone.\n",getpid());
}

