#include "input.h"

#include <string.h>
#include <unistd.h>


#define MIN(a, b) (a < b)? a: b


int 
stdin_or_arg(int argc, char **argv, char *out, int outlen) {
    ssize_t c;

    if (argc < 2) {
        return read(STDIN_FILENO, out, outlen);
    }
    else {
        c = MIN(strlen(argv[1]), outlen);
        strncpy(out, argv[1], c);
        return c;
    }
    
    return 0;
}
