#include <iostream>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
using namespace std;
int main() {
int fd,size;
	char s[]="TTTT\n", buffer[80];
	fd=open("/tmp/temp", O_WRONLY|O_CREAT);
	write(fd,s,sizeof(s));
	close(fd);
	return 0;
}
