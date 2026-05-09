/* heap_botcake -- House of Botcake: combine unsorted bin consolidation with
   tcache double-free to create overlapping heap chunks, then tcache-poison
   into an arbitrary write.
   Goal: write non-zero to `secret`. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 16
#define MAX_SIZE  512

/* Align secret to 16 bytes — glibc 2.32+ tcache checks pointer alignment. */
long secret __attribute__((aligned(16))) = 0;

typedef struct {
    char   *data;
    size_t  size;
} Note;

Note notes[MAX_NOTES];
static int freed_flag[MAX_NOTES];

static int read_idx(void) {
    int idx = -1;
    scanf("%d", &idx);
    return idx;
}

static void do_alloc(void) {
    printf("index (0-%d): ", MAX_NOTES - 1);
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES) { puts("bad idx"); return; }
    printf("size (1-%d): ", MAX_SIZE);
    int sz = -1;
    scanf("%d", &sz);
    if (sz < 1 || sz > MAX_SIZE) { puts("bad size"); return; }
    notes[idx].data = malloc((size_t)sz);
    notes[idx].size = (size_t)sz;
    freed_flag[idx] = 0;
    printf("chunk at %p\n", notes[idx].data);
}

static void do_free(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx].data) { puts("bad"); return; }
    free(notes[idx].data);
    freed_flag[idx] = 1;
    /* BUG: intentionally do not null notes[idx].data — double-free possible */
    puts("freed");
}

static void _drain(void) { int c; do { c = getchar(); } while (c != '\n' && c != EOF); }

static void do_edit(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx].data || freed_flag[idx]) { puts("bad"); return; }
    _drain();
    printf("data: ");
    read(0, notes[idx].data, notes[idx].size);
}

static void do_show(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx].data) { puts("bad"); return; }
    printf("note[%d]: ", idx);
    write(1, notes[idx].data, notes[idx].size);
    puts("");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf("secret is at %p\n", (void *)&secret);

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
            if (secret) {
                puts("FLAG{botcake_master}");
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
