/*
 * fsop_starshard — HTB University / “Starshard”-style FSOP lab (educational).
 *
 * Deliberately mirrors the public write-up pattern (format string → OOB FILE* leak →
 * fclose UAF → malloc+fgets reclaim → fputs trigger), e.g.:
 *   https://medium.com/... (seks99x, FSOP Advanced Heap & File Struct)
 *
 * This binary does **not** ship a flag or a “win” symbol — the goal is practicing the
 * chain (wide_data / _IO_wfile_jumps / _IO_wdoallocbuf), not popping a shell here.
 *
 * Mitigations: PIE, NX, Full RELRO, stack canary (stack buffers in feed path).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char tinkerer_name[0x10];
    char spell_name[0x18];
    FILE *core_log;
    char *spell_fragment;
    size_t fragment_sz;
} console_state_t;

static console_state_t g_cs;

static void setup(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

static void menu(void) {
    puts("\n1) arm_routine   2) feed_fragment   3) cancel_routine   4) commit_routine   5) exit");
    printf("> ");
}

static void arm_routine(void) {
    g_cs.core_log = fopen("starshard_core.txt", "a");
    if (!g_cs.core_log) {
        perror("fopen");
        exit(1);
    }
    setvbuf(g_cs.core_log, NULL, _IONBF, 0);

    printf("Enter Starshard Routine Name: ");
    fflush(stdout);

    size_t i = 0;
    while (i < sizeof(g_cs.spell_name)) {
        int c = fgetc(stdin);
        if (c == -1 || c == '\n') {
            break;
        }
        g_cs.spell_name[i++] = (char)c;
    }
    /* If i == sizeof(spell_name), no trailing NUL — %s in next printf reads into core_log */
    printf("[*] Routine Armed — %s\n", g_cs.spell_name);
}

static void feed_fragment(void) {
    if (!g_cs.core_log) {
        puts("[!] No active Starshard routine.");
        return;
    }
    g_cs.spell_fragment = NULL;
    g_cs.fragment_sz = 0;

    char size_str[16];
    memset(size_str, 0, sizeof(size_str));

    printf("Wish-Script Fragment Size: ");
    fflush(stdout);
    if (!fgets(size_str, sizeof(size_str), stdin)) {
        puts("[!] Invalid input.");
        return;
    }
    g_cs.fragment_sz = strtoull(size_str, NULL, 10);
    if (g_cs.fragment_sz >= 0x1f5) {
        puts("[!] Fragment exceeds safe sparkle limit.");
        return;
    }
    g_cs.spell_fragment = (char *)malloc(g_cs.fragment_sz);
    if (!g_cs.spell_fragment) {
        perror("malloc");
        exit(1);
    }
    printf("Input Wish-Script Fragment:\n");
    fflush(stdout);
    if (!fgets(g_cs.spell_fragment, (int)g_cs.fragment_sz - 1, stdin)) {
        puts("[!] Fragment input error.");
    } else {
        puts("[*] Fragment Stored.");
    }
}

static void cancel_routine(void) {
    if (!g_cs.core_log) {
        puts("[!] No active routine.");
        return;
    }
    fclose(g_cs.core_log);
    puts("[*] Routine Cancelled.");
    /* Intentional UAF: core_log left dangling (see write-ups). */
}

static void commit_routine(void) {
    if (!g_cs.core_log) {
        puts("[!] No active routine.");
        return;
    }
    if (!g_cs.spell_fragment) {
        puts("[!] No fragment.");
        return;
    }
    fputs(g_cs.spell_fragment, g_cs.core_log);
    fflush(g_cs.core_log);
    puts("[*] Routine Committed to Starshard Core.");
}

int main(void) {
    setup();
    memset(&g_cs, 0, sizeof(g_cs));

    puts("=== FSOP lab (Starshard-style chain) ===");

    printf("Tinselwick Tinkerer Name: ");
    fflush(stdout);
    if (!fgets(g_cs.tinkerer_name, (int)sizeof(g_cs.tinkerer_name), stdin)) {
        puts("[!] Input error.");
        return 1;
    }
    g_cs.tinkerer_name[strcspn(g_cs.tinkerer_name, "\n")] = '\0';

    printf("=== Welcome ");
    printf(g_cs.tinkerer_name);
    puts("!");

    for (;;) {
        menu();
        char line[8];
        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }
        switch (line[0]) {
            case '1':
                arm_routine();
                break;
            case '2':
                feed_fragment();
                break;
            case '3':
                cancel_routine();
                break;
            case '4':
                commit_routine();
                break;
            case '5':
                puts("[*] Exiting Starshard Console.");
                return 0;
            default:
                puts("[!] Invalid option.");
                break;
        }
    }
    return 0;
}
