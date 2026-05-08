/* heap_fastbin_dup -- fastbin double-free (A→B→A) with safe-linking bypass.
   The exploit fills tcache[chunk_0x30] first (7 frees), then the A→B→A
   double-free lands in the fastbin.
   Goal: write to win_flag via a fake chunk planted in BSS. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 24
#define NOTE_SIZE 0x28   /* chunk size = ALIGN_UP(0x28+8,16) = 0x30, fastbin[1] */

/* Fake chunk in BSS.  malloc's fastbin path checks the size field of the
   chunk it is about to return; size=0x31 matches the 0x30 fastbin class.
   malloc returns fake_chunk+0x10, landing on win_flag. */
struct {
    unsigned long _prev;   /* offset 0x00: ignored */
    unsigned long _size;   /* offset 0x08: 0x31 = 0x30|PREV_INUSE */
    int           win_flag;/* offset 0x10: write non-zero here to win */
    int           _pad;
    unsigned long _fd;     /* extra fields keep the struct large enough */
    unsigned long _bk;
} fake_chunk __attribute__((aligned(16))) = {0, 0x31, 0, 0, 0, 0};

char *notes[MAX_NOTES];
int   freed[MAX_NOTES];  /* used only by do_edit to block UAF writes */

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
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) { puts("bad"); return; }
    /* BUG: no freed-check here → same note can be freed multiple times
       (double-free).  freed[] only prevents UAF writes via do_edit. */
    free(notes[idx]);
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
    read(0, notes[idx], NOTE_SIZE);
}

static void do_show(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) { puts("bad"); return; }
    printf("note[%d]: ", idx);
    write(1, notes[idx], NOTE_SIZE);
    puts("");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf("fake_chunk at %p\n", (void *)&fake_chunk);

    int choice;
    while (1) {
        puts("\n1) alloc  2) free  3) edit  4) show  5) win");
        printf("> ");
        if (scanf("%d", &choice) != 1) break;
        switch (choice) {
        case 1: do_alloc(); break;
        case 2: do_free();  break;
        case 3: do_edit();  break;
        case 4: do_show();  break;
        case 5:
            if (fake_chunk.win_flag) {
                puts("FLAG{fastbin_dup_master}");
                return 0;
            }
            puts("nope");
            break;
        default:
            puts("bye"); return 0;
        }
    }
    return 0;
}
