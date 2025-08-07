// Replace encrypt() function with:
void decrypt(char *ciphertext, char *key, char *plaintext) {
    for (int i = 0; i < strlen(ciphertext); i++) {
        int ct = charToInt(ciphertext[i]);
        int kt = charToInt(key[i]);
        plaintext[i] = intToChar((ct - kt + 27) % 27);
    }
    plaintext[strlen(ciphertext)] = '\0';
}

// dec_client.c (same as enc_client.c, but used with dec_server)

// compileall
// Save this as a shell script and make it executable:
// chmod +x compileall
