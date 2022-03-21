#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "redis.h"

int main(int argc, char **argv, char **envp)
{
  redis_server_run(0);
  return 0;
}
