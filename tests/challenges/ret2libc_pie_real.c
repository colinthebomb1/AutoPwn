/* ret2libc_pie_real — realistic leak-based PIE ret2libc.
   Stage 1: leak puts@GLIBC via puts@plt(puts@got), then re-enter vuln.
   Stage 2: call system("/bin/sh") from the resolved libc.

   The binary prints `main is at %p` once so the solver can compute the PIE base.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Provide a pop rdi; ret gadget in the main executable. */
void __attribute__((used, naked)) _gadgets(void) {
    __asm__("pop %rdi; ret");
}

void vuln(void) {
    char buf[64];

    puts("name?");
    /* Overflow primitive for ROP challenges. */
    read(0, buf, 400);
    puts("bye");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    /* PIE base leak for the first stage. */
    printf("main is at %p\n", (void *)main);
    puts("ret2libc-pie-real");

    vuln();
    return 0;
}

