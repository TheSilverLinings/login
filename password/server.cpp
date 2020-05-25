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
#include "login.pb.h"
#define PORT 7444
#define QUEUE 20
#define BUFFER_SIZE 1024
using std::cout;
using std::endl;

int conn;

void thread_task()
{
}

// check the username and password from text
bool check_user_pwd(const std::string &username,const std::string &password)
{
    std::string tuser,tpwd;
    std::ifstream ifile;
    ifile.open("up.txt");
    while(!ifile.eof())
    {
        ifile>>tuser;
        ifile>>tpwd;
        if((tuser==username)&&(tpwd==password))
        {
            ifile.close();
            return true;
        }
    }
    ifile.close();
    return false;
}

// confirm the user
int confirm_user(int fd)
{
    int cnt = 0;
    char sendbuf[BUFFER_SIZE],recvbuf[BUFFER_SIZE];
    std::string username,password;

    login::LoginRequest login_request;
    login::LoginReply login_reply;
    // auto user = login_request.mutable_user();
// 就是这里循环了3次？dui 就是 c 端循环1次,这里循环2次
// show me the case , run it in bash
// 运行代码我看看
// bash可以split, 有

    while(cnt++<3){ //这个是服务端，还要一个bash
        cout<<cnt<<endl; //ok 怎么打开两个bash
        memset(sendbuf,0,sizeof(sendbuf));
        memset(recvbuf,0,sizeof(recvbuf));
        auto status = recv(fd,recvbuf,BUFFER_SIZE,0);
        cout << "recv complete , status :" << status << endl;
        login_request.ParseFromArray(recvbuf,BUFFER_SIZE);
        auto user = login_request.user();
        username = user.username();
        password = user.password();
        //会不会是这些嵌套消息的语法用错了？
        // 不会，这个不会导致两次， 第一次应该没接受消息，第二次才接受消息，TCP？ OK，看懂了
        // 不应该啊。按理说是第一次就收了，第二次没有，你看我给你的截图 对 TCP
        // 你编译运行下， 有一种情况，你按enter后这个信号被接受，但是没有实际输入，你可以构建默认数据试试
        // ...原来如此。。。
       // 你试试 
       //好像不是这个原因
       //我来
       // ok可以了
       // 我修改前有没有这个问题
       // 不好说，当时没有测试那么仔细，一遍正确直接通过
       
       // 另一次是错误一次，然后正确一次，也能正确通过 //我回去再看看吧，现在太晚了
       // 如果错误两次，那server就退出了，最后正确也没用 --> 这种情况没有测试
        cout<<login_request.user().username()<<endl;
        cout<<password<<endl;
        bool flag = check_user_pwd(username,password);

        if(flag)
        {
            login_reply.set_msg("T");
            login_reply.SerializeToArray(sendbuf,BUFFER_SIZE);
            send(fd,sendbuf,BUFFER_SIZE,0);
            cout<<"User: "<<username<<" log in."<<endl;
            break;
        }   
        else
        {
            login_reply.set_msg("F");
            login_reply.SerializeToArray(sendbuf,BUFFER_SIZE);
            send(fd,sendbuf,BUFFER_SIZE,0);
        }    
        
    }
}
 
int main()
{
    printf("%d\n",SOCK_STREAM);  // 基于TCP的有保障面向连接的SOCKET，SOCK_DGRAM基于UDP；
    int ss = socket(AF_INET, SOCK_STREAM, 0);
    /*
        #include<netinet/in.h>
        socket ：创建套接字函数
            int socket(int domian,int type,int protocol)
        socket 参数：
            1. int domain/address family --> 套接字要使用的协议簇，AF_INET(TCP/IP-IPv4)、AF_INET6(TCP/IP-IPv6)、AF_UNIX
            2. int type --> 套接字类型，SOCK_STREAM、SOCK_DGRAM、SOCK_RAW
            3. int protocol --> 一般为0，当创建SOCK_RAW，domain/address family 不清楚时，该参数k可以确定协议种类。
        socket 返回：
            1. 成功返回套接字
            2. 失败返回-1
    */
    struct sockaddr_in server_sockaddr;
    /*
        #include <netinet/in.h>
            struct sockaddr_in
            {
                unsigned short         sin_family;   地址类型：   对应套接字 domain/address-family字段  
                unsigned short int     sin_port;     端口号：     0~65535
                struct in_addr         sin_addr;     32位IP地址： 127.0.0.1
                unsigned char          sin_zero[8];  填充字节：   一般该值为0
            };
    */
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(PORT); //主机字节序与网络字节序转换。待仔细看。
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY); //INADDR_ANY，本机所有网卡，待仔细看。
    /*
        #include <arpa/inet.h>
        struct in_addr 
        {
            in_addr_t s_addr; 一般为 32位的unsigned int，其字节顺序为网络顺序（network byte ordered)，即该无符号整数采用大端字节序
        };
    */

    if(bind(ss, (struct sockaddr* ) &server_sockaddr, sizeof(server_sockaddr))==-1)
    {
        perror("bind");
        exit(1);
    }
    /*
        #include<sys/socket.h>
        bind ：函数绑定模板，待仔细看。
            int bind(int sockfd, const struct sockaddr, socklen_t addrlen);
        bind 参数：
            int sockfd：套接字的索引
            const struct sockaddr：一个指向特定协议的地址结构的指针
            socklen_t addrlen：该地址结构的长度
        bind 返回：
            1. 成功返回 0
            2. 失败返回-1
    */
    if(listen(ss, QUEUE) == -1)  //使用 listen() 函数
    {
        perror("listen");
        exit(1);
    }
    /*
        #include<sys/socket.h>
        listen ：让套接字进入被动监听状态，待仔细看。
            int listen(int sock, int backlog);
        listen 参数：
            int sockfd：套接字的索引
            int backlog：连接队列内核的上限
        listen 返回：
            1. 成功返回 0
            2. 失败返回-1
    */
 
    struct sockaddr_in client_addr;
    socklen_t length = sizeof(client_addr);
   
    conn = accept(ss, (struct sockaddr*)&client_addr, &length); // 调用 accept() 函数，就
    /*
        <sys/types.h>
        <sys/socket.h>
        accept ：可以随时响应客户端的请求，待仔细看。
            int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
        accept 参数：
            int sockfd：套接字的索引
            struct sockaddr *addr：指向结构体sockaddr的指针
            socklen_t *addrlen：addr参数指向的内存空间的长度
        accept 返回：
            1. 成功返回套接字描述符
            2. 失败返回-1        
    */
    if( conn < 0 )
    {
        perror("connect");
        exit(1);
    }

    confirm_user(conn);

    cout<<"continue"<<endl;
    while(1)
    close(conn);
    close(ss);
    return 0;
}

/*
    ssize_t write(int fd, const void *buf, size_t nbytes);
*/