#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint8_t akms_C0[4] = {0x91abd5d6, 0x8f339a27, 0xcad69edd, 0xe8df4b8c};

uint8_t akms_S0[256] = {86, 115, 144, 173, 202, 231, 4, 33, 62, 91, 120, 149, 178, 207, 236, 9, 38, 67, 96, 125, 154, 183, 212, 241, 14, 43, 72, 101, 130, 159, 188, 217, 246, 19, 48, 77, 106, 135, 164, 193, 222, 251, 24, 53, 82, 111, 140, 169, 198, 227, 0, 29, 58, 87, 116, 145, 174, 203, 232, 5, 34, 63, 92, 121, 150, 179, 208, 237, 10, 39, 68, 97, 126, 155, 184, 213, 242, 15, 44, 73, 102, 131, 160, 189, 218, 247, 20, 49, 78, 107, 136, 165, 194, 223, 252, 25, 54, 83, 112, 141, 170, 199, 228, 1, 30, 59, 88, 117, 146, 175, 204, 233, 6, 35, 64, 93, 122, 151, 180, 209, 238, 11, 40, 69, 98, 127, 156, 185, 214, 243, 16, 45, 74, 103, 132, 161, 190, 219, 248, 21, 50, 79, 108, 137, 166, 195, 224, 253, 26, 55, 84, 113, 142, 171, 200, 229, 2, 31, 60, 89, 118, 147, 176, 205, 234, 7, 36, 65, 94, 123, 152, 181, 210, 239, 12, 41, 70, 99, 128, 157, 186, 215, 244, 17, 46, 75, 104, 133, 162, 191, 220, 249, 22, 51, 80, 109, 138, 167, 196, 225, 254, 27, 56, 85, 114, 143, 172, 201, 230, 3, 32, 61, 90, 119, 148, 177, 206, 235, 8, 37, 66, 95, 124, 153, 182, 211, 240, 13, 42, 71, 100, 129, 158, 187, 216, 245, 18, 47, 76, 105, 134, 163, 192, 221, 250, 23, 52, 81, 110, 139, 168, 197, 226, 255, 28, 57};
uint8_t akms_S0i[256] = {50, 103, 156, 209, 6, 59, 112, 165, 218, 15, 68, 121, 174, 227, 24, 77, 130, 183, 236, 33, 86, 139, 192, 245, 42, 95, 148, 201, 254, 51, 104, 157, 210, 7, 60, 113, 166, 219, 16, 69, 122, 175, 228, 25, 78, 131, 184, 237, 34, 87, 140, 193, 246, 43, 96, 149, 202, 255, 52, 105, 158, 211, 8, 61, 114, 167, 220, 17, 70, 123, 176, 229, 26, 79, 132, 185, 238, 35, 88, 141, 194, 247, 44, 97, 150, 203, 0, 53, 106, 159, 212, 9, 62, 115, 168, 221, 18, 71, 124, 177, 230, 27, 80, 133, 186, 239, 36, 89, 142, 195, 248, 45, 98, 151, 204, 1, 54, 107, 160, 213, 10, 63, 116, 169, 222, 19, 72, 125, 178, 231, 28, 81, 134, 187, 240, 37, 90, 143, 196, 249, 46, 99, 152, 205, 2, 55, 108, 161, 214, 11, 64, 117, 170, 223, 20, 73, 126, 179, 232, 29, 82, 135, 188, 241, 38, 91, 144, 197, 250, 47, 100, 153, 206, 3, 56, 109, 162, 215, 12, 65, 118, 171, 224, 21, 74, 127, 180, 233, 30, 83, 136, 189, 242, 39, 92, 145, 198, 251, 48, 101, 154, 207, 4, 57, 110, 163, 216, 13, 66, 119, 172, 225, 22, 75, 128, 181, 234, 31, 84, 137, 190, 243, 40, 93, 146, 199, 252, 49, 102, 155, 208, 5, 58, 111, 164, 217, 14, 67, 120, 173, 226, 23, 76, 129, 182, 235, 32, 85, 138, 191, 244, 41, 94, 147, 200, 253};

struct akms_state {
    uint32_t S[4];
    uint32_t T[4];
    uint32_t K[16][4];
    uint32_t last[4];
    uint32_t next[4];
    int rounds;
};

uint32_t akms_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t akms_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}


void akms_sub(struct akms_state *state) {
    state->S[0] = ((uint32_t)(akms_S0[(state->S[0] & 0xFF000000) >> 24] << 24) + ((uint32_t)akms_S0[(state->S[0] & 0x00FF0000) >> 16] << 16) + ((uint32_t)akms_S0[(state->S[0] & 0x0000FF00) >> 8] << 8) + ((uint32_t)akms_S0[(state->S[0] & 0x000000FF)]));
    state->S[1] = ((uint32_t)(akms_S0[(state->S[1] & 0xFF000000) >> 24] << 24) + ((uint32_t)akms_S0[(state->S[1] & 0x00FF0000) >> 16] << 16) + ((uint32_t)akms_S0[(state->S[1] & 0x0000FF00) >> 8] << 8) + ((uint32_t)akms_S0[(state->S[1] & 0x000000FF)]));
    state->S[2] = ((uint32_t)(akms_S0[(state->S[2] & 0xFF000000) >> 24] << 24) + ((uint32_t)akms_S0[(state->S[2] & 0x00FF0000) >> 16] << 16) + ((uint32_t)akms_S0[(state->S[2] & 0x0000FF00) >> 8] << 8) + ((uint32_t)akms_S0[(state->S[2] & 0x000000FF)]));
    state->S[3] = ((uint32_t)(akms_S0[(state->S[3] & 0xFF000000) >> 24] << 24) + ((uint32_t)akms_S0[(state->S[3] & 0x00FF0000) >> 16] << 16) + ((uint32_t)akms_S0[(state->S[3] & 0x0000FF00) >> 8] << 8) + ((uint32_t)akms_S0[(state->S[3] & 0x000000FF)]));
}

void akms_sub_inv(struct akms_state *state) {
    state->S[0] = ((uint32_t)(akms_S0i[(state->S[0] & 0xFF000000) >> 24] << 24) + ((uint32_t)akms_S0i[(state->S[0] & 0x00FF0000) >> 16] << 16) + ((uint32_t)akms_S0i[(state->S[0] & 0x0000FF00) >> 8] << 8) + ((uint32_t)akms_S0i[(state->S[0] & 0x000000FF)]));
    state->S[1] = ((uint32_t)(akms_S0i[(state->S[1] & 0xFF000000) >> 24] << 24) + ((uint32_t)akms_S0i[(state->S[1] & 0x00FF0000) >> 16] << 16) + ((uint32_t)akms_S0i[(state->S[1] & 0x0000FF00) >> 8] << 8) + ((uint32_t)akms_S0i[(state->S[1] & 0x000000FF)]));
    state->S[2] = ((uint32_t)(akms_S0i[(state->S[2] & 0xFF000000) >> 24] << 24) + ((uint32_t)akms_S0i[(state->S[2] & 0x00FF0000) >> 16] << 16) + ((uint32_t)akms_S0i[(state->S[2] & 0x0000FF00) >> 8] << 8) + ((uint32_t)akms_S0i[(state->S[2] & 0x000000FF)]));
    state->S[3] = ((uint32_t)(akms_S0i[(state->S[3] & 0xFF000000) >> 24] << 24) + ((uint32_t)akms_S0i[(state->S[3] & 0x00FF0000) >> 16] << 16) + ((uint32_t)akms_S0i[(state->S[3] & 0x0000FF00) >> 8] << 8) + ((uint32_t)akms_S0i[(state->S[3] & 0x000000FF)]));
}

void akms_rotl_words(struct akms_state *state) {
    state->S[1] = akms_rotl(state->S[1], 8);
    state->S[2] = akms_rotl(state->S[2], 16);
    state->S[3] = akms_rotl(state->S[3], 24);
}

void akms_rotr_words(struct akms_state *state) {
    state->S[1] = akms_rotr(state->S[1], 8);
    state->S[2] = akms_rotr(state->S[2], 16);
    state->S[3] = akms_rotr(state->S[3], 24);
}

void akms_rotate_words(struct akms_state *state) {
    state->T[0] = state->S[0];
    state->T[1] = state->S[1];
    state->T[2] = state->S[2];
    state->T[3] = state->S[3];

    state->S[1] = state->T[0];
    state->S[2] = state->T[1];
    state->S[3] = state->T[2];
    state->S[0] = state->T[3];

}

void akms_rotate_words_inv(struct akms_state *state) {
    state->T[0] = state->S[0];
    state->T[1] = state->S[1];
    state->T[2] = state->S[2];
    state->T[3] = state->S[3];

    state->S[0] = state->T[1];
    state->S[1] = state->T[2];
    state->S[2] = state->T[3];
    state->S[3] = state->T[0];
}

void akms_mix(struct akms_state *state) {
    state->S[2] += state->S[3];
    state->S[3] += state->S[2];
    state->S[0] += state->S[1];
    state->S[1] += state->S[0];

    state->S[0] += state->S[2];
    state->S[1] += state->S[3];
    state->S[2] += state->S[1];
    state->S[3] += state->S[0];
}

void akms_mix_inv(struct akms_state *state) {
    state->S[3] -= state->S[0];
    state->S[2] -= state->S[1];
    state->S[1] -= state->S[3];
    state->S[0] -= state->S[2];

    state->S[1] -= state->S[0];
    state->S[0] -= state->S[1];
    state->S[3] -= state->S[2];
    state->S[2] -= state->S[3];
}

void akms_add_key(struct akms_state *state, int r) {
    state->S[0] ^= state->K[r][0];
    state->S[1] ^= state->K[r][1];
    state->S[2] ^= state->K[r][2];
    state->S[3] ^= state->K[r][3];
}

void akms_ksa(struct akms_state *state, uint8_t *key, int rounds) {
    state->K[0][0] = ((key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3]);
    state->K[0][1] = ((key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7]);
    state->K[0][2] = ((key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11]);
    state->K[0][3] = ((key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15]);
    state->K[15][0] = ((key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19]);
    state->K[15][1] = ((key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23]);
    state->K[15][2] = ((key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27]);
    state->K[15][3] = ((key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31]);

    state->S[0] = state->K[0][0] + akms_C0[0];
    state->S[1] = state->K[0][1] + akms_C0[1];
    state->S[2] = state->K[0][2] + akms_C0[2];
    state->S[3] = state->K[0][3] + akms_C0[3];

    state->T[0] = state->K[15][0];
    state->T[1] = state->K[15][1];
    state->T[2] = state->K[15][2];
    state->T[3] = state->K[15][3];

    int r, i;
    int c = 0;
    for (r = 1; r < rounds - 1; r++) {
        for (i = 0; i < 4; i++) {
            state->S[i] ^= akms_rotl(state->T[i], 15) + akms_rotl(state->S[i], 14);
            state->S[(i + 1) & 0x03] ^= akms_rotl(state->T[(i + 1) & 0x03], 10) + akms_rotl(state->S[(i + 1) & 0x03], 9);
            state->S[(i + 2) & 0x03] ^= akms_rotl(state->T[(i + 2) & 0x03], 15) + akms_rotl(state->S[(i + 2) & 0x03], 21);
            state->S[(i + 3) & 0x03] ^= akms_rotl(state->T[(i + 3) & 0x03], 12) + akms_rotl(state->S[(i + 3) & 0x03], 11);
            state->K[r][i] = state->S[i];
        }
    }

}

void akms_encrypt_block(struct akms_state *state, int rounds) {
    for (int r = 0; r < rounds; r++) {
        akms_sub(state);
        akms_rotl_words(state);
        akms_rotate_words(state);
        akms_mix(state);
        akms_add_key(state, r);
    }
}

void akms_decrypt_block(struct akms_state *state, int rounds) {
    for (int r = rounds - 1; r != -1; r--) {
        akms_add_key(state, r);
        akms_mix_inv(state);
        akms_rotate_words_inv(state);
        akms_rotr_words(state);
        akms_sub_inv(state);
    }
}

void akms_load_block(struct akms_state *state, uint8_t *block) {
    state->S[0] = ((block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3]);
    state->S[1] = ((block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7]);
    state->S[2] = ((block[8] << 24) + (block[9] << 16) + (block[10] << 8) + block[11]);
    state->S[3] = ((block[12] << 24) + (block[13] << 16) + (block[14] << 8) + block[15]);
}

void akms_unload_block(struct akms_state *state, uint8_t *block) {
    block[0] = state->S[0] >> 24;
    block[1] = state->S[0] >> 16;
    block[2] = state->S[0] >> 8;
    block[3] = state->S[0];
    block[4] = state->S[1] >> 24;
    block[5] = state->S[1] >> 16;
    block[6] = state->S[1] >> 8;
    block[7] = state->S[1];
    block[8] = state->S[2] >> 24;
    block[9] = state->S[2] >> 16;
    block[10] = state->S[2] >> 8;
    block[11] = state->S[2];
    block[12] = state->S[3] >> 24;
    block[13] = state->S[3] >> 16;
    block[14] = state->S[3] >> 8;
    block[15] = state->S[3];
}

void akms_load_iv(struct akms_state *state, uint8_t *iv) {
    state->last[0] = ((iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3]);
    state->last[1] = ((iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7]);
    state->last[2] = ((iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11]);
    state->last[3] = ((iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15]);
}

void akms_cbc_last(struct akms_state *state) {
    state->S[0] ^= state->last[0];
    state->S[1] ^= state->last[1];
    state->S[2] ^= state->last[2];
    state->S[3] ^= state->last[3];
}

void akms_cbc_next(struct akms_state *state) {
    state->last[0] = state->S[0];
    state->last[1] = state->S[1];
    state->last[2] = state->S[2];
    state->last[3] = state->S[3];
}

void akms_cbc_next_inv(struct akms_state *state) {
    state->next[0] = state->S[0];
    state->next[1] = state->S[1];
    state->next[2] = state->S[2];
    state->next[3] = state->S[3];
}

void akms_cbc_last_inv(struct akms_state *state) {
    state->last[0] = state->next[0];
    state->last[1] = state->next[1];
    state->last[2] = state->next[2];
    state->last[3] = state->next[3];
}

void akms_cbc_encrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
    struct qloq_ctx ctx;
    struct qloq_ctx Sctx;
    struct qloq_ctx TMPActx;
    struct qloq_ctx TMPBctx;
    load_pkfile(pkfile, &ctx, &TMPActx);
    load_skfile(skfile, &TMPBctx, &Sctx);
    uint8_t key[32];
    uint8_t key_padded[32];
    uint8_t pad_nonce[32];
    uint8_t keyctxt[768];
    urandom(key, 32);
    urandom(pad_nonce, 32);
    BIGNUM *bn_keyptxt;
    BIGNUM *bn_keyctxt;
    bn_keyptxt = BN_new();
    bn_keyctxt = BN_new();
    mypad_encrypt(key, pad_nonce, key_padded);
    BN_bin2bn(key_padded, 32, bn_keyptxt);
    cloak(&ctx, bn_keyctxt, bn_keyptxt);
    BN_bn2bin(bn_keyctxt, keyctxt);

    struct akms_state state;
    state.rounds = 16;
    akms_ksa(&state, key, state.rounds);
    int blocklen = 16;
    int bufsize = 16;
    uint8_t iv[blocklen];
    urandom(iv, blocklen);
    akms_load_iv(&state, iv);
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fwrite(pad_nonce, 1, 32, outfile);
    fwrite(keyctxt, 1, 768, outfile);
    fwrite(iv, 1, blocklen, outfile);
    fseek(infile, 0, SEEK_END);
    uint32_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    uint32_t blocks = datalen / blocklen;
    int extra = datalen % blocklen;
    int extrabytes = blocklen - (datalen % blocklen);
    if (extra != 0) {
       blocks += 1;
    }
    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[16];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
            for (int p = 0; p < extrabytes; p++) {
                block[(blocklen-1-p)] = (uint8_t *)extrabytes;
            }
        }
        fread(block, 1, bufsize, infile);
        akms_load_block(&state, block);
        akms_cbc_last(&state);
        akms_encrypt_block(&state, state.rounds);
        akms_cbc_next(&state);
        akms_unload_block(&state, block);
        fwrite(block, 1, blocklen, outfile);
    }
    fclose(infile);
    fclose(outfile);
    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    qx_hmac_file_write(outputfile, kdf_key);
    sign_hash_write(&Sctx, outputfile);
}

void akms_cbc_decrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
    struct qloq_ctx ctx;
    struct qloq_ctx Sctx;
    struct qloq_ctx TMPActx;
    struct qloq_ctx TMPBctx;
    load_pkfile(pkfile, &TMPActx, &Sctx);
    load_skfile(skfile, &ctx, &TMPBctx);
    verify_sig_read(&Sctx, inputfile);
    uint8_t key[32];
    uint8_t key_padded[32];
    uint8_t pad_nonce[32];
    uint8_t keyctxt[768];

    struct akms_state state;
    state.rounds = 16;
    int blocklen = 16;
    uint8_t iv[blocklen];
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint32_t datalen = ftell(infile);
    datalen = datalen - blocklen - 768 - 32 - 32 - 768 - 32;
    fseek(infile, 0, SEEK_SET);
    fread(pad_nonce, 1, 32, infile);
    fread(keyctxt, 1, 768, infile);
    fread(iv, 1, blocklen, infile);
    akms_load_iv(&state, iv);
    uint32_t blocks = datalen / blocklen;
    int extra = datalen % blocklen;
    if (extra != 0) {
       blocks += 1;
    }

    BIGNUM *bn_keyptxt;
    BIGNUM *bn_keyctxt;
    bn_keyptxt = BN_new();
    bn_keyctxt = BN_new();
    BN_bin2bn(keyctxt, 768, bn_keyctxt);
    decloak(&ctx, bn_keyptxt, bn_keyctxt);
    BN_bn2bin(bn_keyptxt, key_padded);
    mypad_decrypt(key_padded, pad_nonce, key);
    fclose(infile);

    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    if (qx_hmac_file_read_verify_offset(inputfile, kdf_key, (768 + 32)) == -1) {
        printf("Error: QX HMAC message is not authentic.\n");
        exit(2);
    }
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, (768 + blocklen + 32), SEEK_SET);
    akms_ksa(&state, key, state.rounds);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[16];
        fread(block, 1, blocklen, infile);
        akms_load_block(&state, block);
        akms_cbc_next_inv(&state);
        akms_decrypt_block(&state, state.rounds);
        akms_cbc_last(&state);
        akms_cbc_last_inv(&state);
        akms_unload_block(&state, block);

        if (b == (blocks - 1)) {
            int padcheck = block[blocklen - 1];
            int g = blocklen - 1;
            int count = 0;
            for (int p = 0; p < padcheck; p++) {
                if ((int)block[g] == padcheck) {
                    count += 1;
                }
                g = g - 1;
            }
            if (padcheck == count) {
                blocklen = blocklen - count;
            }
        }
        fwrite(block, 1, blocklen, outfile);
    }
    fclose(infile);
    fclose(outfile);
}
