/* heap_tcache_poison -- tcache poisoning via UAF (glibc safe-linking aware).
   Goal: overwrite is_admin and print a flag. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 8
#define NOTE_SIZE 0x60

int is_admin = 0;
char *notes[MAX_NOTES];

static void menu(void) {
    puts("\n1) alloc");
    puts("2) free");
    puts("3) edit");
    puts("4) show");
    puts("5) check admin");
    printf("> ");
}

static int read_idx(void) {
    int idx = -1;
    if (scanf("%d", &idx) != 1) {
        return -1;
    }
    return idx;
}

static void do_alloc(void) {
    int idx;
    printf("index (0-%d): ", MAX_NOTES - 1);
    idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES) {
        puts("bad idx");
        return;
    }
    notes[idx] = malloc(NOTE_SIZE);
    printf("chunk at %p\n", notes[idx]);
}

static void do_free(void) {
    int idx;
    printf("index: ");
    idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) {
        puts("bad");
        return;
    }
    free(notes[idx]);
    /* BUG: UAF; intentionally do not clear notes[idx]. */
    puts("freed");
}

static void _drain_stdin_line(void) {
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);
}

static void do_edit(void) {
    int idx;
    printf("index: ");
    idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) {
        puts("bad");
        return;
    }
    _drain_stdin_line();
    printf("data: ");
    read(0, notes[idx], NOTE_SIZE);
}

static void do_show(void) {
    int idx;
    printf("index: ");
    idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) {
        puts("bad");
        return;
    }
    printf("note[%d]: ", idx);
    write(1, notes[idx], NOTE_SIZE);
    puts("");
}

int main(void) {
    int choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf("is_admin is at %p\n", &is_admin);

    while (1) {
        menu();
        choice = read_idx();
        switch (choice) {
            case 1:
                do_alloc();
                break;
            case 2:
                do_free();
                break;
            case 3:
                do_edit();
                break;
            case 4:
                do_show();
                break;
            case 5:
                if (is_admin) {
                    puts("FLAG{tcache_poison_master}");
                    return 0;
                }
                puts("not admin");
                break;
            default:
                puts("bye");
                return 0;
        }
    }
}
