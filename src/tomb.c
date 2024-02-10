#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include "common/common.c"
#include "pki/qloqRSA.c"
#include "hash/qx.c"
#include "ciphers/akms_cbc.c"

void usage() {
    printf("DarkTomb v0.3 - by KryptoMagick\n\n");
    printf("Algorithms:\n***********\nakms-cbc         256 bit\n\n");
    printf("Usage:\ntomb <algorithm> -e <input file> <output file> <pk file> <sk file>\n");
    printf("tomb <algorithm> -d <input file> <output file> <pk file> <sk file>\n");
}

int main(int argc, char *argv[]) {
    int kdf_iters = 100000;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    if (argc != 7) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name, *pkfile_name, *skfile_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    pkfile_name = argv[5];
    skfile_name = argv[6];
    if (access(infile_name, F_OK) == -1 ) {
        printf("%s not found\n", infile_name);
        exit(1);
    }
/*
    infile = fopen(infile_name, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fclose(infile);
*/
/*
    struct termios tp, save;
    tcgetattr(STDIN_FILENO, &tp);
    save = tp;
    tp.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);

    unsigned char * passphrase[256];
    printf("Enter secret key passphrase: ");
    scanf("%s", passphrase);
    tcsetattr(STDIN_FILENO, TCSANOW, &save);
*/
    if (strcmp(algorithm, "akms-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            akms_cbc_encrypt(infile_name, outfile_name, pkfile_name, skfile_name);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            akms_cbc_decrypt(infile_name, outfile_name, pkfile_name, skfile_name);
        }
    }
    printf("\n");
    return 0;
}
