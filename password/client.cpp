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

const size_t MYPORT = 7456;
const size_t BUFFER_SIZE = 2048;

using std::cout;
using std::endl;

// TODO(Zheng): 不要这样批量注释代码，使用git做版本控制
// TODO(Zheng): 使用glog代替cout日志

int32_t confirm_password(int fd) {
  int cnt = 0;  // log the try times.

  char sendbuf[BUFFER_SIZE], recvbuf[BUFFER_SIZE];
  std::string username, password;

  login::LoginRequest login_request;
  login::LoginReply login_reply;
  auto user = login_request.mutable_user();

  while (cnt++ < 3) {
    memset(sendbuf, 0, sizeof(sendbuf));
    memset(recvbuf, 0, sizeof(recvbuf));
    // memset(sendbuf,0,sizeof(sendbuf));
    // memset(sendbuf,0,sizeof(sendbuf));

    std::cout << "Input username : ";
    std::getline(std::cin, username);
    // cin.getline(username,sizeof(username));
    // fgets(username, sizeof(username), stdin); //读入了回出
    // write(fd,username,sizeof(username));
    // read(fd,recvbuf,sizeof(recvbuf));
    // fputs(recvbuf, stdout);

    std::cout << "Input password : ";
    std::getline(std::cin, password);

    // TODO(Zheng): encrypto password as base64

    // TODO(Zheng): check whether user name is legal

    // cin.getline(password,sizeof(password));
    // fgets(password, sizeof(password), stdin);
    // write(fd,password,sizeof(password));
    // read(fd,recvbuf,sizeof(recvbuf));

    user->set_username(username);
    user->set_password(password);
    user->SerializeToArray(sendbuf, BUFFER_SIZE);

    if (send(fd, sendbuf, BUFFER_SIZE, 0) <= 0) {
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

  /*
  服务器ip，inet_addr用于IPv4的IP转换（十进制转换为二进制）
   127.0.0.1是本地预留地址
  连接服务器，成功返回0，错误返回-1
  */
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

  // {/*每次读取一行，读取的数据保存在buf指向的字符数组中，成功，则返回第一个参数buf；*/
  // send(sock_cli, sendbuf, strlen(sendbuf),0); ///发送

  // write(sock_cli, sendbuf, strlen(sendbuf));
  // if(strcmp(sendbuf,"exit\n")==0)
  //      break;
  // recv(sock_cli, recvbuf, sizeof(recvbuf),0); ///接收
  // read(sock_cli, recvbuf, sizeof(recvbuf));
  // fputs(recvbuf, stdout);
  // memset(sendbuf, 0,
  // sizeof(sendbuf));//接受或者发送完毕后把数组中的数据全部清空（置0）
  //}

  // close(sock_cli);
  return 0;
}