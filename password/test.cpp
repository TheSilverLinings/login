#include<iostream>
#include<fstream>
#include<string>

using namespace std;

int main()
{
    ifstream ifile;
    ifile.open("up.txt");
    if(!ifile.is_open())
    {
        cout<<"can not open file"<<endl;
        return 0;
    }
    else 
    {
        cout<<"file open"<<endl;
    }

    // string line;
    // while(getline(ifile,line))
    // {
    //     cout<<line<<endl;
    // } 
    // ifile.close();
    char euser[20];
    char epwd[20];
    while(!ifile.eof())
    {
        ifile>>euser;
        ifile>>epwd;
        cout<<euser<<endl;
        cout<<epwd<<endl;
    }
    ifile.close();
}