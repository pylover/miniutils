#include <string.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>


#define BEARER_TOKEN_SIZE 128 
#define HMAC_LEN 32
#define HMAC_ENCODEDLEN (((HMAC_LEN + 2) / 3) * 4)


static const char base64url_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
        "jklmnopqrstuvwxyz0123456789-_";


int
base64url_encode(const unsigned char *input, size_t input_length,
        char *output) {
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
base64url_decode(char *input, size_t input_length, unsigned char *output) {
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

    return output_length;
}


void
calculate_hmac_sha256(const unsigned char *data, int data_len,
        const unsigned char *key, int key_len, unsigned char *result) {
    unsigned int len = HMAC_LEN;
    HMAC(EVP_sha256(), key, key_len, data, data_len, result, &len);
}


int
jwt_generate(const char *payload, const char *secret, char *token) {
    /* Fixed header is only supported in this version */
    const char *header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    size_t header_length = strlen(header);
    char encoded_header[BEARER_TOKEN_SIZE];
    base64url_encode((const unsigned char *)header, header_length,
                     encoded_header);

    size_t payload_length = strlen(payload);
    char encoded_payload[BEARER_TOKEN_SIZE];
    base64url_encode((const unsigned char *)payload, payload_length,
                     encoded_payload);

    /* Concatenate header and payload with a period ('.') separator */
    char data[BEARER_TOKEN_SIZE * 2 + 2];
    sprintf(data, "%s.%s", encoded_header, encoded_payload);

    unsigned char hmac[HMAC_LEN];
    unsigned int hmac_length;
    HMAC(EVP_sha256(), secret, strlen(secret), (const unsigned char *)data,
         strlen(data), hmac, &hmac_length);

    char encoded_signature[BEARER_TOKEN_SIZE];
    base64url_encode(hmac, hmac_length, encoded_signature);

    sprintf(token, "%s.%s.%s", encoded_header, encoded_payload,
            encoded_signature);

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

    /* Concatenate header and payload with a period separator */
    char msg[BEARER_TOKEN_SIZE];
    strcpy(msg, header);
    strcat(msg, ".");
    strcat(msg, payload);

    /* Calculate the HMAC SHA256 */
    unsigned char hmac[HMAC_LEN];
    calculate_hmac_sha256((unsigned char*)msg, strlen(msg),
            (unsigned char*)secret, strlen(secret), hmac);

    /* Base64url encode the HMAC */
    char encoded_hmac[HMAC_ENCODEDLEN];
    base64url_encode(hmac, sizeof(hmac), encoded_hmac);

    /* Compare the provided signature with the calculated one */
    if (strcmp(signature, encoded_hmac) != 0) {
        return -1;
    }

    return 0;
}


int
main() {
    char payload[] = "{\"user\":\"admin\",\"iat\":1422779638}";
    char jwt[BEARER_TOKEN_SIZE];
    char secret[] = "7{yX5OB_zh?Hv]|5PO`H:Jn?Z=LNaB^_";

    if (jwt_generate(payload, secret, jwt) != 0) {
        printf("JWT generation failed.\n");
        return -1;
    }

    printf("Generated JWT: %s\n", jwt);

    if (jwt_verify(jwt, "7{yX5OB_zh?Hv]|5PO`H:Jn?Z=LNaB^_") != 0) {
        printf("JWT verification failed.\n");
        return -1;
    }

    printf("JWT verification succeeded.\n");
    return 0;
}

