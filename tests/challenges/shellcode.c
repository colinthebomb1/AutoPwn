/* shellcode — buffer overflow with NX disabled.
   Agent must inject and execute shellcode.
   The buffer address is helpfully leaked. */

#include <stdio.h>
#include <string.h>

void vuln() {
    char buf[128];
    printf("Buffer is at: %p\n", buf);
    puts("Give me your payload:");
    gets(buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
