/* Intentionally vulnerable read-only helper for isolated S3/S7 fixtures.
 * A real set-user-ID binary is required: Linux ignores that bit on scripts.
 * There is no shell, command execution, network action or write operation.
 */
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: iot-diag /absolute/file/path\n");
        return 2;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "iot-diag: root effective UID required\n");
        return 1;
    }
    FILE *input = fopen(argv[1], "rb");
    if (input == NULL) {
        perror("iot-diag");
        return 1;
    }
    char buffer[4096];
    size_t count;
    while ((count = fread(buffer, 1, sizeof(buffer), input)) != 0) {
        if (fwrite(buffer, 1, count, stdout) != count) {
            fclose(input);
            return 1;
        }
    }
    int failed = ferror(input);
    if (fclose(input) != 0 || fflush(stdout) != 0) {
        failed = 1;
    }
    return failed ? 1 : 0;
}
