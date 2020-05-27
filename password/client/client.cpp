/* 局域网TCP客户端 */

/*
在TCP三次握手完成后会进入等待连接队列，等待服务端调用accpet与之建立连接，这时候是server端调用accept跟客户端建立
通信，客户端并不需要调用accpet，因为有很多个客户端要跟服务端建立连接，这时候服务端就会有一个队列，对已经经过三次握
手的才可以建立连接（类似缓存信息），这个是由服务端来确认的，客户端并不知道什么时候服务端才能跟它建立连接，在服务端
没有调用accept与之连接或者还未排队到它，只能是一直等待，直到服务端准备好了才能跟客户端建立连接，所以主动权在服务端
*/

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include "openssl/rsa.h"  
#include "openssl/pem.h" 
#include "login.pb.h"
#define KEY_LENGTH  1024               // 密钥长度  
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径  
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径  

const size_t MYPORT = 4213;
const size_t BUFFER_SIZE = 2048;

using std::cout;
using std::endl;

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

int32_t confirm_password(int fd) {
    int cnt = 0;  // log the try times.
    char sendbuf[BUFFER_SIZE], recvbuf[BUFFER_SIZE];
    std::string mypubkey,prikey,pubkey;
    std::string username, password;

    login::LoginRequest login_request;
    login::LoginReply login_reply;
    auto user = login_request.mutable_user();

    //share public key with server
    sharePublicKey(fd,mypubkey,prikey,pubkey);

  while (cnt++ < 3)  {
      memset(sendbuf, 0, sizeof(sendbuf));
      memset(recvbuf, 0, sizeof(recvbuf));

      std::cout << "Input username : ";
      std::getline(std::cin, username);

      std::cout << "Input password : ";
      std::getline(std::cin, password);

      // TODO(Zheng): encrypto password as base64
      // TODO(Zheng): check whether user name is legal

      user->set_username(rsa_pub_encrypt(username,pubkey));
      user->set_password(rsa_pub_encrypt(password,pubkey));
      login_request.SerializeToArray(sendbuf,BUFFER_SIZE);
      int flag = send(fd,sendbuf,BUFFER_SIZE-1,0); //循环2次
      if (flag <= 0) {
        perror("send failed: ");
        continue;
      }

    recv(fd, recvbuf, BUFFER_SIZE, 0);
    login_reply.ParseFromArray(recvbuf, BUFFER_SIZE);
    std::string msg = login_reply.msg();
    msg = rsa_pri_decrypt(msg,prikey);

    if (msg == "T") {
      return 1;
    } else if (msg == "F") {
      std::cerr << "Wrong Username or Password." << endl;
    }
    
  }

  std::cerr << "Exit for trying many times." << endl;
  return -1;
}

int main() {
  int sock_cli = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));

  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(MYPORT);  // 服务器端口
  servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    perror("connect failed: ");
    exit(1);
  }

  auto flag = confirm_password(sock_cli);
  if (flag == -1)
    close(sock_cli);
  else if (flag == 1)
    cout << "continue doing other." << endl;
  return 0;
}