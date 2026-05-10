/* heap_apple2_hard -- House of Apple 2 without a win function.
   Identical vulnerability to heap_apple2 (UAF, no null-on-free), but there is
   no get_shell() helper.  The solver must target libc directly:
     1. Leak libc via large chunk in unsorted bin.
     2. Resolve _IO_list_all, _IO_wfile_jumps, and a libc execution target.
     3. Place system or a validated one_gadget in fake _wide_vtable.__doallocate (+0x68).
     4. Corrupt _IO_list_all via tcache poison, trigger FSOP on exit().
   Compiled: no-PIE, Full RELRO, NX; glibc 2.34+ (no __malloc_hook / __free_hook). */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_NOTES 16
#define MAX_SIZE  0x500

typedef struct {
    char   *data;
    size_t  size;
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
    if (idx < 0 || idx >= MAX_NOTES) { puts("bad idx"); return; }
    printf("size (1-0x%x): ", (int)MAX_SIZE);
    int sz = -1;
    scanf("%d", &sz);
    if (sz < 1 || sz > (int)MAX_SIZE) { puts("bad size"); return; }
    notes[idx].data = malloc((size_t)sz);
    notes[idx].size = (size_t)sz;
    printf("chunk at %p\n", (void *)notes[idx].data);
}

static void do_free(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx].data) { puts("bad"); return; }
    free(notes[idx].data);
    /* BUG: no null-on-free — enables UAF read (libc/heap leak) and UAF write (tcache poison). */
    puts("freed");
}

static void _drain(void) { int c; do { c = getchar(); } while (c != '\n' && c != EOF); }

static void do_edit(void) {
    printf("index: ");
    int idx = read_idx();
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx].data) { puts("bad"); return; }
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
    setvbuf(stdin,  NULL, _IONBF, 0);

    int choice;
    while (1) {
        puts("\n1) alloc  2) free  3) edit  4) show  5) exit");
        printf("> ");
        if (scanf("%d", &choice) != 1) break;
        switch (choice) {
        case 1: do_alloc(); break;
        case 2: do_free();  break;
        case 3: do_edit();  break;
        case 4: do_show();  break;
        case 5: puts("bye"); exit(0);
        default: puts("bye"); return 0;
        }
    }
    return 0;
}
