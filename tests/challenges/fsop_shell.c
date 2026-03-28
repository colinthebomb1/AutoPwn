/* fsop_shell.c — overwrite libc stdout FILE (byor-style); fflush(stdout) for trigger.
 *
 * All prompts/menus go to stderr so after edit(3) corrupts stdout, the process can
 * still print the menu and recv flush(5). (If menu used stdout, the next menu()
 * would crash once _IO_2_1_stdout_ is overwritten.)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLOTS     8
#define CHUNKSZ   0x100

static void *notes[SLOTS];

static void menu(void) {
    const char m[] =
        "\n1) alloc\n2) free\n3) edit\n4) show\n5) flush\n6) exit\n> ";
    write(2, m, sizeof(m) - 1);
}

static int read_int(void) {
    int v = -1;
    scanf("%d", &v);
    return v;
}

static void do_alloc(void) {
    fprintf(stderr, "index (1-%d): ", SLOTS - 1);
    fflush(stderr);
    int i = read_int();
    if (i < 1 || i >= SLOTS) { fputs("bad\n", stderr); return; }
    if (notes[i]) { fputs("in use\n", stderr); return; }
    notes[i] = malloc(CHUNKSZ);
    if (!notes[i]) { fputs("oom\n", stderr); return; }
    memset(notes[i], 0, CHUNKSZ);
    fprintf(stderr, "chunk at %p\n", notes[i]);
}

static void do_free(void) {
    fputs("index: ", stderr);
    fflush(stderr);
    int i = read_int();
    if (i < 0 || i >= SLOTS || !notes[i]) { fputs("bad\n", stderr); return; }
    if (i == 0) { fputs("cannot free slot 0 (libc stdout)\n", stderr); return; }
    free(notes[i]);
    fputs("freed\n", stderr);
}

static void do_edit(void) {
    fputs("index: ", stderr);
    fflush(stderr);
    int i = read_int();
    if (i < 0 || i >= SLOTS || !notes[i]) { fputs("bad\n", stderr); return; }
    fread(notes[i], 1, CHUNKSZ, stdin);
}

static void do_show(void) {
    fputs("index: ", stderr);
    fflush(stderr);
    int i = read_int();
    if (i < 0 || i >= SLOTS || !notes[i]) { fputs("bad\n", stderr); return; }
    fwrite(notes[i], 1, CHUNKSZ, stdout);
    fflush(stdout);
}

static void do_flush(void) {
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    memset(notes, 0, sizeof(notes));
    notes[0] = (void *)stdout;

    fprintf(stderr, "notes[0]  @ %p  (same as stdout pointer)\n", (void *)notes[0]);
    fprintf(stderr, "stdout    @ %p\n", (void *)stdout);
    fprintf(stderr, "notes     @ %p\n", (void *)notes);

    for (;;) {
        menu();
        switch (read_int()) {
            case 1: do_alloc(); break;
            case 2: do_free();  break;
            case 3: do_edit();  break;
            case 4: do_show();  break;
            case 5: do_flush(); break;
            case 6: fputs("bye\n", stderr); return 0;
            default: fputs("?\n", stderr); break;
        }
    }
}
