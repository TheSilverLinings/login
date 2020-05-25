//////////////////////////////////////////////////////////////////////////////
// Created by zhouzzz on 2018/6/18.
// Description : 服务器类
//////////////////////////////////////////////////////////////////////////////
 
 
#include <stdio.h>
#include <winsock2.h>
#include <thread>
#include <iostream>
#include <vector>
#include <cstring>
#include <string>
#include "msg.pb.h"
#pragma comment(lib,"ws2_32.lib")
using namespace word3;
static int connectCount = 0;//当前连接客户端的数量
std::vector <SOCKET> clients;//将所有正在连接的客户端放在容器中
 
void delClient(SOCKET clientsoc)//当客户端断开连接时，从容器中删除客户端
{
	for (int i = 0; i < clients.size(); i++)
	{
		if (clients[i] == clientsoc)
		{
			clients.erase(clients.begin() + i);
			break;
		}
	}
}
void sendMsg(char *buf)//向所有客户端发送消息
{
	std::vector<SOCKET>::iterator it;
	for (it = clients.begin(); it != clients.end(); it++) {
		if (send(*it, buf, strlen(buf) + 1, 0) <= 0)
		{
			printf("发送错误!\n");
			break;
		}
	}
}
void listenThread(char *buf, SOCKET clientsoc, SOCKADDR_IN clientaddr, int number)//监听线程，监听客户端的连接请求
{
	printf("----------------------------------------------------------\n");
	printf("连接成功，客户端ip:%s\n客户端编号%d,当前连接数量%d\n",inet_ntoa(clientaddr.sin_addr), number, connectCount);//inet_ntoa:返回ip的字符串形式，客户端的编号按连接先后顺序赋值
	printf("----------------------------------------------------------\n");
	memset(buf, '\0', sizeof(buf));
	//客户端刚连接上时，发送一条数据，将客户端的编号告诉客户端
	sendmsg smsg;
	char ss[1024];
	memset(ss, '\0', sizeof(ss));
	smsg.set_clientid(number);
	char tt[16] = "欢迎您，客户端";//固定格式，一个中文字符占2个char，最后还要留一个char为结束符'\0'
	tt[14] = number + '0';
	smsg.set_msg(tt);
	smsg.SerializeToArray(ss, 1024);//序列化
	if (send(clientsoc, ss, strlen(ss) + 1, 0) <= 0)
	{
		printf("发送错误!\n");
		return;
	}
	//向所有客户端发送服务器的消息
	memset(ss, '\0', sizeof(ss));
	while (1) {
		scanf("%s", buf);
		int x = 0;
		smsg.set_clientid(x);
		smsg.set_msg(buf);
		smsg.SerializeToArray(buf, 1024);
		sendMsg(buf);
	}
}
 
void recvFromClient(SOCKET clientsoc, char *buf, int number)//接受一个客户端的消息并转发给所有客户端
{
	while (1)
	{
		if (recv(clientsoc, buf, 1024, 0) <= 0)
		{
			printf("客户端%d关闭连接!\n", number);
			delClient(clientsoc);
			connectCount--;
			closesocket(clientsoc);
			return;
		}
		sendMsg(buf);
	}
}
int main()
{
	SOCKET serversoc;
	SOCKET clientsoc;
	SOCKADDR_IN serveraddr;
	SOCKADDR_IN clientaddr;
	char buf[1024];
	int len;
	static int listenCount = 0;
	
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);	//初始化WS2_32.DLL
										//创建套接字
	if ((serversoc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) <= 0)
	{
		printf("套接字socket创建失败!\n");
		return -1;
	}
	//命名协议，IP，端口
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(9102);
	serveraddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	//绑定套接字
	if (bind(serversoc, (SOCKADDR *)&serveraddr, sizeof(serveraddr)) != 0)
	{
		printf("套接字绑定失败!\n");
		return -1;
	}
	printf("开始监听...\n");
	//监听请求
	if (listen(serversoc, 1) != 0)
	{
		printf("监听失败!\n");
		return -1;
	}
	len = sizeof(SOCKADDR_IN);
	//接收请求
	while (1) {
		if ((clientsoc = accept(serversoc, (SOCKADDR *)&clientaddr, &len)) <= 0)
		{
			printf("接受连接失败!\n");
			return -1;
		}
		else {
			listenCount++;
			connectCount++;
			clients.push_back(clientsoc);//将刚连接上的客户端加入容器
			std::thread task(listenThread, buf, clientsoc, clientaddr, listenCount);//每当有客户端请求连接时，就开启一个线程接受连接
			task.detach();//detach()不会造成堵塞，join()会主线程造成堵塞
			std::thread task02(recvFromClient, clientsoc, buf, listenCount);//开启一个线程监听该客户端的消息
			task02.detach();
		}
	}
	WSACleanup();     //释放WS2_32.DLL
	system("pause");
	return 0;
}