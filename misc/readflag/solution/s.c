#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/user.h>
#include <fcntl.h>

long exploit_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {
    long ret;
    errno = 0;
    ret = ptrace(request, pid, addr, data);
    if (errno != 0) {
        perror("ptrace");
        _exit(1);
    }
    return ret;
}

int exploit_wait(void) {
    int wstatus;
    if (wait(&wstatus) == -1) {
        perror("wait");
        _exit(1);
    }
    if (WIFEXITED(wstatus)) {
        return 0;
    }
    if (!WIFSTOPPED(wstatus)) {
        fprintf(stderr, "error: child crashed\n");
        _exit(1);
    }
    return 1;
}

int main() {
    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork");
        _exit(1);
    }

    if (child_pid == 0) {
        int fd;
        if ((fd = open("/dev/null", O_WRONLY)) == -1) {
            perror("open");
            _exit(1);
        }
        if (dup2(fd, 1) == -1) {
            perror("dup2");
            _exit(1);
        }
        close(fd);
        ptrace(PTRACE_TRACEME);
        execve("./readflag", NULL, NULL);
    } else {
        struct user_regs_struct regs;
        unsigned long long rip_1ff = 0;
        if (!exploit_wait()) {
            fprintf(stderr, "error: child exited\n");
            _exit(1);
        }
        while (1) {
            exploit_ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
            if (!exploit_wait()) {
                putchar('\n');
                break;
            }
            exploit_ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            if (!rip_1ff && (regs.rip & 0xfffULL) == 0x1ffULL && regs.rdx == 'z') {
                rip_1ff = regs.rip;
            }
            if (regs.rip == rip_1ff) {
                putchar((char) regs.rdx);
            }
        }
    }
}
