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
#include <string>
#include "login.pb.h"
#define MYPORT  7456
#define BUFFER_SIZE 1024
using std::cout;
using std::endl;

int confirm_password(int fd)
{
    int cnt = 0; //log the try times.
    char sendbuf[BUFFER_SIZE],recvbuf[BUFFER_SIZE];
    // char username[20],password[20];
    std::string username,password;
    login::User user;
    while(cnt<3)
    {
        
        memset(sendbuf,0,sizeof(sendbuf));
        memset(recvbuf,0,sizeof(recvbuf));
        // memset(sendbuf,0,sizeof(sendbuf));
        // memset(sendbuf,0,sizeof(sendbuf));

        std::cout<<"Input username : ";
        std::getline(std::cin,username);
        // cin.getline(username,sizeof(username));
        // fgets(username, sizeof(username), stdin); //读入了回出
        // write(fd,username,sizeof(username));
        // read(fd,recvbuf,sizeof(recvbuf));
        // fputs(recvbuf, stdout);

        std::cout<<"Input password : ";
        std::getline(std::cin,password);
        // cin.getline(password,sizeof(password));
        // fgets(password, sizeof(password), stdin); 
        // write(fd,password,sizeof(password));
        // read(fd,recvbuf,sizeof(recvbuf));

        user.set_username(username);
        user.set_password(password);
        user.SerializeToArray(sendbuf,BUFFER_SIZE);
        if(send(fd,sendbuf,BUFFER_SIZE,0)<=0)
        {
            perror("send");
            cout<<"send error"<<endl;
        }

        recv(fd,recvbuf,BUFFER_SIZE,0);
        user.ParseFromArray(recvbuf,BUFFER_SIZE);

        if (user.msg() == "T")
            return 1;
        else if (user.msg() == "F")
        {
            cout<<"Wrong Username or Password."<<endl;
        }
        // if(strcmp(recvbuf,"T")==0)
        //     return 1;
           
        // else if(strcmp(recvbuf,"F")==0)
        //     cout<<"Wrong Username or Password."<<endl;
        // else 
        //     {
        //         cout<<"unexpected error occured"<<endl;
        //         close(fd);
        //         exit(1);
        //     }
        cnt++;
    }
    cout<<"Exit for trying many times."<<endl;
    return -1;
}
 
int main()
{
    int sock_cli = socket(AF_INET,SOCK_STREAM, 0);
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(MYPORT);  //服务器端口
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");  //服务器ip，inet_addr用于IPv4的IP转换（十进制转换为二进制）
    //127.0.0.1是本地预留地址
    //连接服务器，成功返回0，错误返回-1
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


       // {/*每次读取一行，读取的数据保存在buf指向的字符数组中，成功，则返回第一个参数buf；*/
            // send(sock_cli, sendbuf, strlen(sendbuf),0); ///发送
            
            // write(sock_cli, sendbuf, strlen(sendbuf));
           // if(strcmp(sendbuf,"exit\n")==0)
          //      break;
            // recv(sock_cli, recvbuf, sizeof(recvbuf),0); ///接收
            // read(sock_cli, recvbuf, sizeof(recvbuf));
            // fputs(recvbuf, stdout);
           // memset(sendbuf, 0, sizeof(sendbuf));//接受或者发送完毕后把数组中的数据全部清空（置0）
        //}
    
    // close(sock_cli);
    return 0;
}
/*在TCP三次握手完成后会进入等待连接队列，等待服务端调用accpet与之建立连接，这时候是server端调用accept跟客户端建立
通信，客户端并不需要调用accpet，因为有很多个客户端要跟服务端建立连接，这时候服务端就会有一个队列，对已经经过三次握
手的才可以建立连接（类似缓存信息），这个是由服务端来确认的，客户端并不知道什么时候服务端才能跟它建立连接，在服务端
没有调用accept与之连接或者还未排队到它，只能是一直等待，直到服务端准备好了才能跟客户端建立连接，所以主动权在服务端*/