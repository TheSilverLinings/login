//////////////////////////////////////////////////////////////////////////////
// Created by zhouzzz on 2018/6/18.
// Description : 客户端类
//////////////////////////////////////////////////////////////////////////////
 
 
#include <stdio.h>
#include <iostream>
#include <winsock2.h>
#include <thread>
#include "msg.pb.h"
#pragma comment(lib,"ws2_32.lib")
using namespace word3;
static int number;
 
//监听来自服务器的消息，也可能时服务器转发的客户端的消息，clientid = 0：服务器，clientid = number：本身,clientid = 其他：别的客户端
void recvFromServer(SOCKET clientsocket,char *buf)
{
	sendmsg smsg;
	while (1) {
		memset(buf, '\0', sizeof(buf));
		if (recv(clientsocket, buf, 1024, 0) <= 0)
		{
			printf("关闭连接!\n");
			break;
			closesocket(clientsocket);
		}
		smsg.ParseFromArray(buf, 1024);//反序列化
		if (smsg.clientid() == 0) std::cout << "服务器" << ":";
		else if(smsg.clientid() == number) std::cout << "我" << ":";
		else std::cout << "客户端" << smsg.clientid() << ":";
		std::cout << smsg.msg() << "\n";
	}
}
int main()
{
	SOCKET clientsocket;
	SOCKADDR_IN serveraddr;
	SOCKADDR_IN clientaddr;
	char buf[1024];
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);	//初始化WS2_32.DLL
										//创建套接字
	if ((clientsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) <= 0)
	{
		printf("套接字socket创建失败!\n");
		system("pause");
		return -1;
	}
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(9102);
	serveraddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	//请求连接
	printf("尝试连接中...\n");
	if (connect(clientsocket, (SOCKADDR *)&serveraddr, sizeof(serveraddr)) != 0)
	{
		printf("连接失败!\n");
		system("pause");
		return -1;
	}
	printf("连接成功!\n");
	//刚连接上时，会受到服务器的一条消息，该消息带有本客户端的id，获取并赋值给number
	if (recv(clientsocket, buf, 1024, 0) <= 0)
	{
		printf("关闭连接!\n");
		return -1;
		closesocket(clientsocket);
	}
	sendmsg smsg;
	smsg.ParseFromArray(buf, 1024);
	std::cout << "服务器" << ":" << smsg.msg() << "\n";
	number = smsg.clientid();//id赋值给number
	smsg.Clear();
	std::thread task03(recvFromServer, clientsocket, buf);//开启接收消息线程
	task03.detach();
	//发送数据，因为只需要发送数据给服务器，所以发送消息可以直接放在主线程
	sendmsg smsgs;
	char ss[1024];
	memset(ss, '\0', sizeof(ss));
	printf("请任意输入:\n");
	while (1) {
		scanf("%s", buf);
		smsgs.set_clientid(number);
		smsgs.set_msg(buf);
		smsgs.SerializeToArray(ss, 1024);
		if (send(clientsocket, ss, strlen(ss) + 1, 0) <= 0)
		{
			printf("发送错误!\n");
			break;
		}
	}
	closesocket(clientsocket);
	WSACleanup();    //释放WS2_32.DLL
	system("pause");
	return 0;
}