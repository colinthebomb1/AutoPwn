/* heap_overflow -- heap buffer overflow into a freed neighbour chunk's tcache
   fd pointer, enabling arbitrary tcache poisoning without a direct UAF write.
   Goal: write non-zero to is_admin and print the flag. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 8
#define NOTE_SIZE  0x60  /* chunk size 0x70 */
/* Overflow reads this many extra bytes past NOTE_SIZE into the next chunk. */
#define OVERFLOW   0x18  /* covers next chunk's prev_size(8) + size(8) + fd(8) */

/* Align is_admin to 16 bytes — glibc tcache alignment check in malloc. */
int is_admin __attribute__((aligned(16))) = 0;

char *notes[MAX_NOTES];
int   freed[MAX_NOTES];

static int read_idx(void) {
    int idx = -1;
    scanf("%d", &idx);
    return idx;
}

static void do_alloc(void) {
    printf("index (0-%d): ", MAX_NOTES - 1);
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES) { puts("bad idx"); return; }
    notes[idx] = malloc(NOTE_SIZE);
    freed[idx] = 0;
    printf("chunk at %p\n", notes[idx]);
}

static void do_free(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx] || freed[idx]) { puts("bad"); return; }
    free(notes[idx]);
    notes[idx] = NULL;  /* prevent UAF — only the overflow path can reach freed memory */
    freed[idx] = 1;
    puts("freed");
}

static void _drain(void) { int c; do { c = getchar(); } while (c != '\n' && c != EOF); }

static void do_edit(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx] || freed[idx]) { puts("bad"); return; }
    _drain();
    printf("data: ");
    /* BUG: reads NOTE_SIZE + OVERFLOW bytes, overflowing into the adjacent chunk */
    read(0, notes[idx], NOTE_SIZE + OVERFLOW);
}

static void do_show(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx] || freed[idx]) { puts("bad"); return; }
    printf("note[%d]: ", idx);
    write(1, notes[idx], NOTE_SIZE);
    puts("");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf("is_admin is at %p\n", &is_admin);

    int choice;
    while (1) {
        puts("\n1) alloc  2) free  3) edit  4) show  5) check admin");
        printf("> ");
        if (scanf("%d", &choice) != 1) break;
        switch (choice) {
        case 1: do_alloc(); break;
        case 2: do_free();  break;
        case 3: do_edit();  break;
        case 4: do_show();  break;
        case 5:
            if (is_admin) {
                puts("FLAG{heap_overflow_master}");
                return 0;
            }
            puts("not admin");
            break;
        default:
            puts("bye"); return 0;
        }
    }
    return 0;
}
