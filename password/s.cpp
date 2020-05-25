#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <thread>
#include <iostream>
#include <fstream>
#include <string>
#define PORT 7222
#define QUEUE 20
using namespace std;
int conn;

bool check_user_pwd(char *username,char *password)
{
    char euser[20],epassword[20];
    ifstream ifile;
    ifile.open("up.txt");
    while(!ifile.eof())
    {
        ifile>>euser;
        ifile>>epassword;
        if(strcmp(euser,username)==0)
            if(strcmp(epassword,password)==0)
                {
                    ifile.close();
                    return true;
                }
    }
    ifile.close();
    return false;
}

int confirm_user(int fd)
{
    // char username[20],password[20];
    // char sendbuf[10];
    string username,password,sendbuf;
    int cnt =0;
    while(cnt<3)
    {
        memset(sendbuf,0,sizeof(sendbuf));
        int len = recv(fd, username, strlen(username)+1,0);
        cout<<strlen(username)<<"recv1:"<<len<<endl;
        len = recv(fd, password, strlen(password)+1,0);
        cout<<strlen(password)<<"recv2:"<<len<<endl;
        bool flag = check_user_pwd(username,password);
        if(flag)
        {
            strcpy(sendbuf,"T");
            cout<<sendbuf<<";"<<endl;
            cout<<"User: "<<username<<" log in."<<endl;
            break;
        }   
        else
        {
            strcpy(sendbuf,"F");
            cout<<sendbuf<<";"<<endl;
        }    
        len = send(fd,sendbuf,strlen(sendbuf)+1,0);
        cout<<strlen(sendbuf)<<"send1:"<<len<<endl;
        cnt++;
    }
}
 
int main()
{
    printf("%d\n",SOCK_STREAM); 
    int ss = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_sockaddr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(PORT); 
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    if(bind(ss, (struct sockaddr* ) &server_sockaddr, sizeof(server_sockaddr))==-1)
    {
        perror("bind");
        exit(1);
    }
    if(listen(ss, QUEUE) == -1)  
    {
        perror("listen");
        exit(1);
    }
    struct sockaddr_in client_addr;
    socklen_t length = sizeof(client_addr);
   
    conn = accept(ss, (struct sockaddr*)&client_addr, &length); 

    if( conn < 0 )
    {
        perror("connect");
        exit(1);
    }
 
    confirm_user(conn);
       
    while(1)
    close(conn);
    close(ss);
    return 0;
}
