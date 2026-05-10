/* heap_poison_null_byte -- off-by-one NUL into the next chunk's size field.

   Goal: create overlapping live chunks. The intended path is the classic
   poison-null-byte / Einherjar-style setup:
     1. Allocate A with usable size 0x108, B with chunk size 0x500, and a guard.
     2. Forge a self-linked fake free chunk at A's real chunk header.
     3. Fill A so its last 8 user bytes become B.prev_size = 0x110.
     4. The off-by-one NUL clears B.size's PREV_INUSE bit.
     5. Free B; glibc consolidates backward with the fake chunk at A.
     6. Allocate from the consolidated free chunk; malloc returns A's user pointer
        again, creating two live notes with the same pointer.

   Compiled: no-PIE, Partial RELRO, NX; glibc 2.34+ safe-linking environment. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_NOTES 8
#define MAX_SIZE  0x600

typedef struct {
    char   *data;
    size_t  size;
    int     live;
} Note;

Note notes[MAX_NOTES];

static int read_idx(void) {
    int idx = -1;
    scanf("%d", &idx);
    return idx;
}

static void do_alloc(void) {
    printf("index (0-%d): ", MAX_NOTES - 1);
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || notes[idx].live) { puts("bad idx"); return; }

    printf("size (1-0x%x): ", MAX_SIZE);
    int sz = -1;
    scanf("%d", &sz);
    if (sz < 1 || sz > MAX_SIZE) { puts("bad size"); return; }

    notes[idx].data = malloc((size_t)sz);
    notes[idx].size = (size_t)sz;
    notes[idx].live = 1;
    printf("chunk at %p\n", (void *)notes[idx].data);
}

static void do_free(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx].live) { puts("bad"); return; }

    free(notes[idx].data);
    notes[idx].data = NULL;
    notes[idx].size = 0;
    notes[idx].live = 0;
    puts("freed");
}

static void _drain(void) { int c; do { c = getchar(); } while (c != '\n' && c != EOF); }

static void do_edit(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx].live) { puts("bad"); return; }

    _drain();
    printf("data: ");
    read(0, notes[idx].data, notes[idx].size);
    /* BUG: one-byte poison NUL past the editable region. For a 0x108 request,
       this lands on the next chunk's size LSB and clears PREV_INUSE. */
    notes[idx].data[notes[idx].size] = '\0';
}

static void do_show(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx].live) { puts("bad"); return; }

    printf("note[%d]: ", idx);
    write(1, notes[idx].data, notes[idx].size);
    puts("");
}

static void do_check(void) {
    for (int i = 0; i < MAX_NOTES; i++) {
        if (!notes[i].live) continue;
        for (int j = i + 1; j < MAX_NOTES; j++) {
            if (notes[j].live && notes[i].data == notes[j].data) {
                puts("FLAG{poison_null_byte_overlap}");
                return;
            }
        }
    }
    puts("no overlap");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    int choice;
    while (1) {
        puts("\n1) alloc  2) free  3) edit  4) show  5) check overlap");
        printf("> ");
        if (scanf("%d", &choice) != 1) break;
        switch (choice) {
        case 1: do_alloc(); break;
        case 2: do_free();  break;
        case 3: do_edit();  break;
        case 4: do_show();  break;
        case 5: do_check(); break;
        default: puts("bye"); return 0;
        }
    }
    return 0;
}
