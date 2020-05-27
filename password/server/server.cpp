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
#include "openssl/rsa.h"  
#include "openssl/pem.h" 
#include "login.pb.h"
#define KEY_LENGTH  1024             // 密钥长度  
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径  
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径  

const size_t PORT = 4213;
const size_t BUFFER_SIZE = 2048;
const size_t QUEUE =20;

using std::cout;
using std::endl;

int conn;

std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey)  
{  
    std::string strRet;  
    RSA *rsa = NULL;  
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pubKey.c_str(), -1);  
    // 此处有三种方法  
    // 1, 读取内存里生成的密钥对，再从内存生成rsa  
    // 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa  
    // 3，直接从读取文件指针生成rsa  
    RSA* pRSAPublicKey = RSA_new();  
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);  
  
    int len = RSA_size(rsa);  
    char *encryptedText = (char *)malloc(len + 1);  
    memset(encryptedText, 0, len + 1);  
  
    // 加密函数  
    int ret = RSA_public_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);  
    if (ret >= 0)  
        strRet = std::string(encryptedText, ret);  
  
    // 释放内存  
    free(encryptedText);  
    BIO_free_all(keybio);  
    RSA_free(rsa);  
  
    return strRet;  
}  

std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey)  
{  
    std::string strRet;  
    RSA *rsa = RSA_new();  
    BIO *keybio;  
    keybio = BIO_new_mem_buf((unsigned char *)priKey.c_str(), -1);  
  
    // 此处有三种方法  
    // 1, 读取内存里生成的密钥对，再从内存生成rsa  
    // 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa  
    // 3，直接从读取文件指针生成rsa  
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);  
  
    int len = RSA_size(rsa);  
    char *decryptedText = (char *)malloc(len + 1);  
    memset(decryptedText, 0, len + 1);  
  
    // 解密函数  
    int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);  
    if (ret >= 0)  
        strRet = std::string(decryptedText, ret);  
  
    // 释放内存  
    free(decryptedText);  
    BIO_free_all(keybio);  
    RSA_free(rsa);  
  
    return strRet;  
}  
 
 void generateRSAKey(std::string &pubkey,std::string &prikey)  
{  
    // 公私密钥对    
    size_t pri_len;  
    size_t pub_len;  
    char *pri_key = NULL;  
    char *pub_key = NULL; 
  
    // 生成密钥对    
    RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);  
  
    BIO *pri = BIO_new(BIO_s_mem());  
    BIO *pub = BIO_new(BIO_s_mem());  
  
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);  
    PEM_write_bio_RSAPublicKey(pub, keypair);  
  
    // 获取长度    
    pri_len = BIO_pending(pri);  
    pub_len = BIO_pending(pub);  
  
    // 密钥对读取到字符串    
    pri_key = (char *)malloc(pri_len + 1);  
    pub_key = (char *)malloc(pub_len + 1);  
  
    BIO_read(pri, pri_key, pri_len);  
    BIO_read(pub, pub_key, pub_len);  
  
    pri_key[pri_len] = '\0';  
    pub_key[pub_len] = '\0';  
  
    // 存储密钥对   
    pubkey = pub_key;
    prikey = pri_key; 
    // strKey[0] = pub_key;  
    // strKey[1] = pri_key;  
  
    // 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private key开头的）  
    FILE *pubFile = fopen(PUB_KEY_FILE, "w");  
    if (pubFile == NULL)  
    {  
        assert(false);  
        return;  
    }  
    fputs(pub_key, pubFile);  
    fclose(pubFile);  
  
    FILE *priFile = fopen(PRI_KEY_FILE, "w");  
    if (priFile == NULL)  
    {  
        assert(false);  
        return;  
    }  
    fputs(pri_key, priFile);  
    fclose(priFile);  
  
    // 内存释放  
    RSA_free(keypair);  
    BIO_free_all(pub);  
    BIO_free_all(pri);  
  
    free(pri_key);  
    free(pub_key);  
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

void sharePublicKey(int fd,std::string &mypubkey,std::string &prikey,std::string &pubkey)
{
      char sendbuf[BUFFER_SIZE], recvbuf[BUFFER_SIZE];
      memset(sendbuf,0,sizeof(sendbuf));
      memset(recvbuf,0,sizeof(recvbuf));
      login::PublicKey public_key;
      // send to server
      generateRSAKey(mypubkey,prikey);
      public_key.set_pubkey(mypubkey);
      public_key.SerializeToArray(sendbuf,BUFFER_SIZE);
      send(fd,sendbuf,BUFFER_SIZE-1,0);
      // receive from client
      recv(fd,recvbuf,BUFFER_SIZE,0);
      public_key.ParseFromArray(recvbuf,BUFFER_SIZE);
      pubkey = public_key.pubkey();
}

// confirm the user
int confirm_user(int fd)
{
    int cnt = 0;
    char sendbuf[BUFFER_SIZE],recvbuf[BUFFER_SIZE];
    std::string mypubkey,prikey,pubkey;
    std::string username,password;

    login::PublicKey public_key;
    login::LoginRequest login_request;
    login::LoginReply login_reply;

    ///share public key with server
    sharePublicKey(fd,mypubkey,prikey,pubkey);
    while(cnt++<3){ 
        memset(sendbuf,0,sizeof(sendbuf));
        memset(recvbuf,0,sizeof(recvbuf));
        recv(fd,recvbuf,BUFFER_SIZE,0);
        login_request.ParseFromArray(recvbuf,BUFFER_SIZE);
        auto user = login_request.user();
        username = rsa_pri_decrypt(user.username(),prikey);
        password = rsa_pri_decrypt(user.password(),prikey);
      
        bool flag = check_user_pwd(username,password);

        if(flag)
        {
            std::string msg = rsa_pub_encrypt("T",pubkey);
            login_reply.set_msg(msg);
            login_reply.SerializeToArray(sendbuf,BUFFER_SIZE);
            send(fd,sendbuf,BUFFER_SIZE-1,0);
            cout<<"User: "<<username<<" log in."<<endl;
            break;
        }   
        else
        {
            std::string msg = rsa_pub_encrypt("F",pubkey);
            login_reply.set_msg(msg);
            login_reply.SerializeToArray(sendbuf,BUFFER_SIZE);
            send(fd,sendbuf,BUFFER_SIZE-1,0);
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
 
     // 调用 accept() 函数，就
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
    

    while(1){
        struct sockaddr_in client_addr;
        socklen_t length = sizeof(client_addr);
   
        conn = accept(ss, (struct sockaddr*)&client_addr, &length);
        if( conn < 0 )
        {
            perror("connect");
            exit(1);
        }

        confirm_user(conn);
    }
    cout<<"continue"<<endl;
    while(1)
    close(conn);
    close(ss);
    return 0;
}
