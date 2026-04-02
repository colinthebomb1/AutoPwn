/*
 * Phoenix stack-five (Exploit Education) with an AutoPwn tweak.
 *
 * Original: https://github.com/ExploitEducation/Phoenix/blob/master/stack-five.c
 * ("Can you execve("/bin/sh", ...) ?")
 *
 * The official Phoenix VM runs with ASLR disabled. For local/CI runs we print
 * the buffer address once so the same techniques work with ASLR on.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
    "Welcome to " LEVELNAME " (Phoenix stack-five derived), https://exploit.education"

char *gets(char *);

void start_level() {
    char buffer[128];
    printf("%p\n", (void *)buffer);
    gets(buffer);
}

int main(int argc, char **argv) {
    printf("%s\n", BANNER);
    start_level();
    return 0;
}
