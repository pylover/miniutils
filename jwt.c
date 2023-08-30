#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <clog.h>


#define BASE64_MAXLEN 128
#define TOKENMAXLEN BASE64_MAXLEN * 3


int
base64url_encode(const unsigned char *decoded, char *encoded,
        size_t encoded_length) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, decoded, strlen(decoded));
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);

    /* Replace base64 characters with base64url characters */
    size_t i;
    for (i = 0; i < buffer_ptr->length; i++) {
        if (buffer_ptr->data[i] == '+') {
            buffer_ptr->data[i] = '-';
        }
        else if (buffer_ptr->data[i] == '/') {
            buffer_ptr->data[i] = '_';
        }
        else if (buffer_ptr->data[i] == '=') {
            buffer_ptr->data[i] = '\0';
        }
    }
    
    
    if (encoded_length < buffer_ptr->length) {
        return -1;
    }

    memcpy(encoded, buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    return 0;
}


static const char b64url_table[1024] = {
    ['A']= 0, ['B']= 1, ['C']= 2, ['D']= 3, ['E']= 4, ['F']= 5, ['G']= 6,
    ['H']= 7, ['I']= 8, ['J']= 9, ['K']=10, ['L']=11, ['M']=12, ['N']=13,
    ['O']=14, ['P']=15, ['Q']=16, ['R']=17, ['S']=18, ['T']=19, ['U']=20,
    ['V']=21, ['W']=22, ['X']=23, ['Y']=24, ['Z']=25, ['a']=26, ['b']=27,
    ['c']=28, ['d']=29, ['e']=30, ['f']=31, ['g']=32, ['h']=33, ['i']=34,
    ['j']=35, ['k']=36, ['l']=37, ['m']=38, ['n']=39, ['o']=40, ['p']=41,
    ['q']=42, ['r']=43, ['s']=44, ['t']=45, ['u']=46, ['v']=47, ['w']=48,
    ['x']=49, ['y']=50, ['z']=51, ['0']=52, ['1']=53, ['2']=54, ['3']=55,
    ['4']=56, ['5']=57, ['6']=58, ['7']=59, ['8']=60, ['9']=61, ['-']=62,
    ['_']=63
};


int
base64url_decode(const char *input, size_t input_length,
        unsigned char *output) {
    size_t padding = 0;
    if (input_length % 4 != 0) {
        padding = 4 - (input_length % 4);
    }

    size_t decoded_length = ((input_length + padding) / 4) * 3;

    // Adjust the decoded length for padding
    if (input[input_length - 1] == '=') {
        decoded_length--;
        if (input[input_length - 2] == '=') {
            decoded_length--;
        }
    }

    if (input_length < decoded_length) {
        printf("dddd");
        return -1; // Output buffer too small
    }

    size_t i, j;
    for (i = 0, j = 0; i < input_length; i += 4, j += 3) {
        int n = (b64url_table[(unsigned char) input[i]] << 18) |
                (b64url_table[(unsigned char) input[i + 1]] << 12) |
                (b64url_table[(unsigned char) input[i + 2]] << 6) |
                b64url_table[(unsigned char) input[i + 3]];

        output[j] = (unsigned char) ((n >> 16) & 0xFF);
        if (j + 1 < decoded_length) {
            output[j + 1] = (unsigned char) ((n >> 8) & 0xFF);
        }
        if (j + 2 < decoded_length) {
            output[j + 2] = (unsigned char) (n & 0xFF);
        }
    }
    output[input_length] = '\0';

    return 0;
}


int
jwt_generate(const unsigned char *payload, const char *secret, char *token,
        size_t token_length) {
    /* In this version caller cannot provide header. */
    const unsigned char *header = "{\"alg\": \"HS256\", \"typ\": \"JWT\"}";
    char *encodedheader;
    char *encodedpayload;
    char *encodedsignature;
    unsigned char signature[EVP_MAX_MD_SIZE];

    encodedheader = malloc(BASE64_MAXLEN);
    base64url_encode(header, encodedheader, BASE64_MAXLEN);

    encodedpayload = malloc(BASE64_MAXLEN);
    base64url_encode(payload, encodedpayload, BASE64_MAXLEN);

    /* +4 for the dots and null-terminator. */
    size_t token_maxlen = strlen(encodedheader) + strlen(encodedpayload) +
            strlen(secret) + 4;
    if (token_length < token_maxlen) {
        /* Insufficient token buffer size. */
        return -1;
    }
    
    snprintf(token, token_length, "%s.%s.", encodedheader, encodedpayload);

    HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char*)token,
            strlen(token), signature, NULL);

    encodedsignature = malloc(BASE64_MAXLEN);
    base64url_encode(signature, encodedsignature, BASE64_MAXLEN);
    strcat(token, encodedsignature);

    free(encodedheader);
    free(encodedpayload);
    free(encodedsignature);

    return 0;
}


int main() {
    const char *input = "eyJ1c2VyX2lkIjogMTMsICJpYXQiOiAxNTE2MjM5MDIyfQ";
    size_t input_length = strlen(input);

    // Calculate the maximum possible size for the decoded output
    size_t max_output_length = (input_length / 4) * 3;

    // Allocate a buffer to store the decoded output (add 1 for null-terminator)
    unsigned char output[max_output_length + 1];

    // Decode the Base64URL-encoded input
    int result = base64url_decode(input, input_length, output);

    if (result == 0) {
        // Null-terminate the decoded output

        // Print the decoded output
        printf("Decoded output: %s\n", output);
    } else {
        printf("Decoding failed.\n");
    }

    return 0;
}
