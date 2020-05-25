/*局域网TCP客户端*/
#include <iostream>
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
using namespace std;
 
#define MYPORT  7222
#define BUFFER_SIZE 1024

int confirm_password(int fd)
{
    int cnt = 0; //log the try times.
    char sendbuf[BUFFER_SIZE],recvbuf[20];
    char username[20],password[20];
    while(cnt<3)
    {
        
        memset(sendbuf,0,sizeof(sendbuf));
        memset(recvbuf,0,sizeof(recvbuf));

        std::cout<<"Input username : ";
        cin.getline(username,sizeof(username));

        int len = send(fd,username,strlen(username)+1,0);
        cout<<strlen(username)<<"send1:"<<len<<endl;


        std::cout<<"Input password : ";
        cin.getline(password,sizeof(password));

        len = send(fd,password,strlen(password)+1,0);
        cout<<strlen(password)<<"send2:"<<len<<endl;
        memset(recvbuf,0,sizeof(recvbuf));

        len = recv(fd,recvbuf,strlen(recvbuf)+1,0);
        cout<<strlen(recvbuf)<<"recv1:"<<len<<endl;
        cout<<recvbuf<<";"<<endl;
        if(strcmp(recvbuf,"T")==0)
            return 1;
           
        else if(strcmp(recvbuf,"F")==0)
            cout<<"Wrong Username or Password."<<endl;
        else 
            {
                cout<<"unexpected error occured"<<endl;
            }
        cnt++;
    }
    return -1;
}
 
int main()
{
    int sock_cli = socket(AF_INET,SOCK_STREAM, 0);
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(MYPORT); 
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

    if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("connect");
        exit(1);
    }
 
    int flag = confirm_password(sock_cli);
    if(flag==-1)
        close(sock_cli);
    else if (flag==1)
        cout<<"continue doing other."<<endl;
    return 0;
}
