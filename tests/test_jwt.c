#include <string.h>

#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <clog.h>
#include <cutest.h>


#define HMAC_LEN 32
#define HMAC_ENCODEDLEN (((HMAC_LEN + 2) / 3) * 4)
#define BASE64URL_ENCODEDLEN(str_len) ((((str_len) + 2) / 3) * 4)


int
base64url_encode(char *input, size_t input_length, char *output) {
    /* Create a BIO object for Base64 encoding */
    BIO *bio = BIO_new(BIO_f_base64());
    if (bio == NULL) {
        return -1;
    }

    /* Set the BIO flags to use URL-safe Base64 encoding */
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    /* Create a memory BIO to write the output */
    BIO *mem_bio = BIO_new(BIO_s_mem());
    if (mem_bio == NULL) {
        BIO_free_all(bio);
        return -1;
    }

    /* Chain the memory BIO to the Base64 encoding BIO */
    bio = BIO_push(bio, mem_bio);

    /* Write the input data to the BIO */
    BIO_write(bio, input, input_length);
    BIO_flush(bio);

    /* Retrieve the encoded output from the memory BIO */
    BUF_MEM *mem_buf;
    BIO_get_mem_ptr(bio, &mem_buf);

    /* Convert the standard Base64 alphabet to Base64URL alphabet */
    size_t i;
    for (i = 0; i < mem_buf->length; i++) {
        if (mem_buf->data[i] == '+') {
            output[i] = '-';
        } else if (mem_buf->data[i] == '/') {
            output[i] = '_';
        } else if (mem_buf->data[i] == '=') {
            /* Padding characters; stop here */
            break;
        } else {
            output[i] = mem_buf->data[i];
        }
    }
    output[i] = '\0';

    /* Clean up the BIO objects */
    BIO_free_all(bio);

    return 0;
}


int
base64url_decode(char *input, size_t input_length, char *output) {
    /* Convert the Base64URL alphabet to the standard Base64 alphabet */
    size_t i;
    for (i = 0; i < input_length; i++) {
        if (input[i] == '-') {
            input[i] = '+';
        } else if (input[i] == '_') {
            input[i] = '/';
        }
    }

    /* Create a BIO object for Base64 decoding */
    BIO *bio = BIO_new(BIO_f_base64());
    if (bio == NULL) {
        return -1;
    }

    /* Set the BIO flags for URL-safe Base64 decoding */
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    /* Create a memory BIO to read the input */
    BIO *mem_bio = BIO_new_mem_buf(input, input_length);
    if (mem_bio == NULL) {
        BIO_free_all(bio);
        return -1;
    }

    /* Chain the memory BIO to the Base64 decoding BIO */
    bio = BIO_push(bio, mem_bio);

    /* Read the input and decode into the output buffer */
    int output_length = BIO_read(bio, output, input_length);
    if (output_length < 0) {
        BIO_free_all(bio);
        return -1;
    }

    /* Clean up the BIO objects */
    BIO_free_all(bio);

    return 0;
}


void
calculate_hmac_sha256(char *data, int data_len, char *key, int key_len,
        char *result) {
    int len = HMAC_LEN;
    HMAC(EVP_sha256(), key, key_len, data, data_len, result, &len);
}


int
jwt_generate(char *payload, char *secret) {
    /* Fixed header is only supported in this version */
    char *header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    size_t headerlen;
    size_t payloadlen;

    headerlen = strlen(header);
    payloadlen = strlen(payload);

    char encoded_header[BASE64URL_ENCODEDLEN(headerlen)];
    base64url_encode(header, headerlen, encoded_header);

    char encoded_payload[BASE64URL_ENCODEDLEN(payloadlen)];
    base64url_encode(payload, payloadlen, encoded_payload);

    /* Concatenate header and payload with a period ('.') separator */
    char data[strlen(encoded_header) + strlen(encoded_payload) + 1];
    strcpy(data, encoded_header);
    strcat(data, ".");
    strcat(data, encoded_payload);

    char hmac[HMAC_LEN];
    calculate_hmac_sha256(data, strlen(data), secret, strlen(secret), hmac);


    char encoded_signature[BASE64URL_ENCODEDLEN(HMAC_LEN)];
    base64url_encode(hmac, HMAC_LEN, encoded_signature);

    printf("%s.%s.%s\n", encoded_header, encoded_payload, encoded_signature);
    return 0;
}


int
jwt_verify(char *token, char *secret) {
    char *header;
    char *payload;
    char *signature;
    char *saveptr;

    /* Split the token into header, payload, and signature */
    char *part = strtok_r(token, ".", &saveptr);
    int i;
    for (i = 0; part != NULL; ++i) {
        if (i == 0) {
            header = part;
        }
        else if (i == 1) {
            payload = part;
        }
        else if (i == 2) {
            signature = part;
        }
        part = strtok_r(NULL, ".", &saveptr);
    }

    INFO("%d", i);
    if (i != 3) {
        printf("Invalid JWT Token\n");
        return -1;
    }

    /* Concatenate header and payload with a period separator */
    char msg[strlen(header) + strlen(payload) + 1];
    strcpy(msg, header);
    strcat(msg, ".");
    strcat(msg, payload);

    /* Calculate the HMAC SHA256 */
    unsigned char hmac[HMAC_LEN];
    calculate_hmac_sha256(msg, strlen(msg), secret, strlen(secret), hmac);

    /* Base64url encode the HMAC */
    char encoded_hmac[HMAC_ENCODEDLEN];
    base64url_encode(hmac, sizeof(hmac), encoded_hmac);

    /* Compare the provided signature with the calculated one */
    if (strcmp(signature, encoded_hmac) == 0) {
        printf("OK\n");
        return 0;
    }

    printf("NOK\n");
    return -1;
}


void
test_base64url() {
    char input[] = "foo, bar!";
    char encoded[256];
    char decoded[256];

    eqint(0, base64url_encode(input, strlen(input), encoded));
    eqint(0, base64url_decode(encoded, strlen(encoded), decoded));
    eqstr(input, decoded);
}


void
test_jwt() {
    char payload[] = "{\"foo\": \"bar\", \"baz\": 13}";
    char secret[] = "Isawasawthatsawasaw";
    eqint(0, jwt_generate(payload, secret));

    char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiAiYmFyIiwg"
            "ImJheiI6IDEzfQ.jue0Jt3beCWBmjG5n0a9T7Pmt_jk2m7CpIUt-t1wECk";
    eqint(0, jwt_verify(token, secret));

    char invalidtoken[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiAiY"
        "mFyIiwgImJheiI6IDEzfQ.jue0Jt3beCWBmjG5n0a9T7Pmt_jk2m7CpIUt-t1wECK";
    eqint(-1, jwt_verify(invalidtoken, secret));
}


int
main() {
    test_base64url();
    test_jwt();

    return EXIT_SUCCESS;
}
