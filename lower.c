#include "input.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>


#define RMAX    1024


int main(int argc, char **argv) {
    char inp[RMAX];
    ssize_t c;

    c = stdin_or_arg(argc, argv, inp, RMAX);
    if (c == -1) {
        err(EXIT_FAILURE, "Cannot read input\n");
    }

    if (c == 0) {
        return EXIT_SUCCESS;
    }
    
    int i;
    for (i = 0; i < c; i++) {
        inp[i] = tolower(inp[i]);
    }
    write(STDOUT_FILENO, inp, c);
    return 0;
}

