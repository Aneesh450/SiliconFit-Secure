/* Intentionally vulnerable demo for defensive review. Do not use in production. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char api_key[] = "sk_live_1234567890abcdef";

void copy_input(char *input) {
    char buffer[16];
    strcpy(buffer, input); /* unsafe: no bounds checking */
    printf("Buffer: %s\n", buffer);
}

void run_command(char *user_supplied) {
    char cmd[128];
    sprintf(cmd, "echo %s", user_supplied); /* unsafe: format/command construction */
    system(cmd); /* unsafe: shell command boundary */
}

int main(int argc, char **argv) {
    if (argc > 1) {
        copy_input(argv[1]);
        run_command(argv[1]);
    }
    return 0;
}
