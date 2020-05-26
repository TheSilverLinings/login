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
#include "login.pb.h"

const size_t MYPORT = 4213;
const size_t BUFFER_SIZE = 2048;

using std::cout;
using std::endl;


int32_t confirm_password(int fd) {
    int cnt = 0;  // log the try times.

    char sendbuf[BUFFER_SIZE], recvbuf[BUFFER_SIZE];
    std::string username, password;

    login::LoginRequest login_request;
    login::LoginReply login_reply;
    auto user = login_request.mutable_user();

  while (cnt++ < 3) 
  {
      memset(sendbuf, 0, sizeof(sendbuf));
      memset(recvbuf, 0, sizeof(recvbuf));

      std::cout << "Input username : ";
      std::getline(std::cin, username);

      std::cout << "Input password : ";
      std::getline(std::cin, password);

      // TODO(Zheng): encrypto password as base64
      // TODO(Zheng): check whether user name is legal

      user->set_username(username);
      user->set_password(password);
      // user->SerializeToArray(sendbuf, BUFFER_SIZE);
      login_request.SerializeToArray(sendbuf,BUFFER_SIZE);
      // 这个发送一次的话s端回复几次
      // cout<<strlen(sendbuf)<<endl;
      int flag = send(fd,sendbuf,BUFFER_SIZE-1,0); //循环2次
      if (flag <= 0) {
        perror("send failed: ");
        continue;
      }

    recv(fd, recvbuf, BUFFER_SIZE, 0);
    login_reply.ParseFromArray(recvbuf, BUFFER_SIZE);

    if (login_reply.msg() == "T") {
      return 1;
    } else if (login_reply.msg() == "F") {
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