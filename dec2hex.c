#include "input.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>


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

    printf("0x%lx\n", atol(inp));
    return EXIT_SUCCESS;
}
