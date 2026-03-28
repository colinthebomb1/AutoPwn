/* fsop_win -- heap notes + UAF on FILE* in slot 0; fflush triggers after FSOP. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(void) {
    puts("FLAG{fsop_win_master}");
    exit(0);
}

int notes_count = 8;
void *notes[8];
FILE *file_ptr;

static void menu(void) {
    puts("\n1) alloc");
    puts("2) free");
    puts("3) edit");
    puts("4) show");
    puts("5) flush");
    puts("6) win");
    puts("7) exit");
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
    printf("index (0-%d): ", notes_count - 1);
    idx = read_idx();
    if (idx < 0 || idx >= notes_count) {
        puts("bad idx");
        return;
    }
    if (idx == 0) {
        puts("slot 0 holds file_ptr; use 1-7 for heap chunks");
        return;
    }
    notes[idx] = malloc(0x100);
    if (!notes[idx]) {
        puts("malloc failed");
        return;
    }
    memset(notes[idx], 0, 0x100);
    printf("chunk at %p\n", notes[idx]);
}

static void do_free(void) {
    int idx;
    printf("index: ");
    idx = read_idx();
    if (idx < 0 || idx >= notes_count || !notes[idx]) {
        puts("bad");
        return;
    }
    free(notes[idx]);
    /* BUG: UAF; intentionally do not clear notes[idx]. */
    puts("freed");
}

static void do_edit(void) {
    int idx;
    printf("index: ");
    idx = read_idx();
    if (idx < 0 || idx >= notes_count || !notes[idx]) {
        puts("bad");
        return;
    }
    (void)fread(notes[idx], 1, 0x100, stdin);
}

static void do_show(void) {
    int idx;
    printf("index: ");
    idx = read_idx();
    if (idx < 0 || idx >= notes_count || !notes[idx]) {
        puts("bad");
        return;
    }
    (void)fwrite(notes[idx], 1, 0x100, stdout);
    fflush(stdout);
}

static void do_flush(void) {
    (void)fflush(file_ptr);
}

int main(void) {
    int choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    memset(notes, 0, sizeof(notes));
    file_ptr = fopen("/dev/null", "w");
    if (!file_ptr) {
        perror("fopen");
        return 1;
    }
    notes[0] = (void *)file_ptr;

    printf("win is at %p\n", (void *)win);
    printf("file_ptr is at %p\n", (void *)file_ptr);
    printf("notes[0] holds %p\n", notes[0]);

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
                do_flush();
                break;
            case 6:
                puts("nice try");
                break;
            case 7:
                puts("bye");
                return 0;
            default:
                puts("bad choice");
                break;
        }
    }
}
