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

int hide_package(const char* atom) {
  FILE *fp;
  /* str + max filename * 2 + \0, overkill */
  char cmd[12+255+255+1] = "equery files ";
  strcat(cmd, atom);
  fp = popen(cmd, "r");
  if (fp == NULL) {
    fprintf(stderr, "failed querying files for %s\n", atom);
    return -1;
  }
  char path[PATH_MAX+1];
  memset(path, 0, sizeof(path));
  while (fgets(path, sizeof(path), fp) != NULL) {
    /* \n breaks stat() */
    path[strcspn(path, "\n")] = 0;
    if (is_file(path)) {
      if (mount("/dev/null", path, "none", MS_BIND, "bind") == -1) {
        perror("mount");
      }
    }
  }
  pclose(fp);
  return 0;
}

int main(int argc, char* argv[], char *envp[]) {
  cap_t cap = cap_get_proc();
  cap_flag_value_t cf;
  /* needed for unshare(CLONE_NEWNS) */
  cap_get_flag(cap, CAP_SYS_ADMIN, CAP_EFFECTIVE, &cf);
  if (cf == CAP_CLEAR) {
    fprintf(stderr, "CAP_SYS_ADMIN is cleared\n\
Please set it before executing this binary using:\n\
# setcap cap_sys_admin+eip build/ehide\n");
    exit(EXIT_FAILURE);
  }
  if (argc < 2) {
    fprintf(stdout, "desc: hide installed Portage package files using mount namespaces\n\
page: https://github.com/alfredfo/ehide\n\
usage: ehide <atom 1> <atom 2> <atom 3> ...\n");
    exit(EXIT_FAILURE);
  }
  if (unshare(CLONE_NEWNS) == -1) {
    perror("unshare");
    exit(EXIT_FAILURE);
  }
  /* stops at last arg, argv[argc]. */
  char **arg;
  for (arg = ++argv; *arg; ++arg) {
    if (hide_package(*arg) == -1) {
      fprintf(stderr, "failed hiding package: %s\n", *arg);
      continue;
    }
    printf("package hidden: %s\n", *arg);
  }
  char *shell = getenv("SHELL");
  char *child_argv[] = { NULL };
  if (execve(shell, child_argv, envp) == -1) {
    perror("Could not execute $SHELL");
    exit(EXIT_FAILURE);
  }
  return 0;
}
