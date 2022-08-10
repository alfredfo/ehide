#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>

int is_file(char path[]) {
  struct stat statbuf;
  if (stat(path, &statbuf) == -1) {
    perror("stat");
  }
  return !S_ISDIR(statbuf.st_mode);
}

int main(int argc, char* argv[], char *envp[]) {
  cap_t cap = cap_get_proc();
  cap_flag_value_t cf;
  cap_get_flag(cap, CAP_SYS_ADMIN, CAP_EFFECTIVE, &cf); // needed for unshare(CLONE_NEWNS)
  if (cf == CAP_CLEAR) {
    fprintf(stderr, "CAP_SYS_ADMIN is cleared\n\
Please set it before executing this binary using:\n\
# setcap cap_sys_admin+eip build/ehide\n");
    
    exit(EXIT_FAILURE);
  }
  if (argc != 2) {
    fprintf(stderr, "usage: ehide <ATOM>");
    exit(EXIT_FAILURE);
  }
  const char* atom = argv[1];
  if (unshare(CLONE_NEWNS) == -1) {
    perror("unshare");
    exit(EXIT_FAILURE);
  }
  // TODO: call Python from C
  FILE *fp;
  char cmd[12+255+255+1] = "equery files "; // str + max filename * 2 + \0, overkill
  strcat(cmd, atom);
  printf("%s", cmd);
  
  fp = popen(cmd, "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    return 1;
  }
  char path[PATH_MAX+1];
  memset(path, 0, sizeof(path));
  while (fgets(path, sizeof(path), fp) != NULL) {
    path[strcspn(path, "\n")] = 0; // \n breaks stat()
    if (is_file(path)) {
      mount(path, "/dev/urandom", "none", 0, "bind");
    }
  }
  pclose(fp);

  char *shell = getenv("SHELL");
  char *child_argv[] = { NULL };
  if (execve(shell, child_argv, envp) == -1) {
    perror("Could not execute $SHELL");
    exit(EXIT_FAILURE);
  }
  
  return 0;
}
