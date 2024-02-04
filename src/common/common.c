void urandom (uint8_t *buf, int num_bytes) {
    FILE *randfile;
    randfile = fopen("/dev/urandom", "rb");
    fread(buf, num_bytes, 1, randfile);
    fclose(randfile);
}
