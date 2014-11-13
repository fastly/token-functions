/****
 *
 * Compile with
 * gcc -o token -lcrypto -lcurl -Wno-deprecated-declarations token.c
 *
 ****/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

struct string {
  char *ptr;
  size_t len;
};

static const unsigned char* encoded_key = "RmFzdGx5IFRva2VuIFRlc3Q=";
static const unsigned long  interval    = 60;

unsigned char* decode64(const unsigned char *input, int length);
unsigned char* encode64(const unsigned char *input, int length);
unsigned char* pack64(long value);
void init_string(struct string *s);
void free_string(struct string *s);
int fetch_url(const char* url, struct string *s);

int main(int argc, char** argv) {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  const unsigned char* key    = decode64(encoded_key, strlen(encoded_key));
  const unsigned char* number = pack64((long) tv.tv_sec / interval);

  OpenSSL_add_all_digests();
  unsigned char* digest = HMAC(EVP_sha256(), key, strlen(key), number, 8, NULL, NULL);
  unsigned char* token  = encode64(digest, strlen(digest));

  struct string response;
  init_string(&response);
  fetch_url("http://token.fastly.com/token", &response);

  struct string validation;
  init_string(&validation);
  char* url = calloc(1024, sizeof(char));
  sprintf(url, "http://token.fastly.com?%s", token);
  fetch_url(url, &validation);

  fprintf(stderr, "Your Token:   %s\n", token);
  fprintf(stderr, "Fastly Token: %s\n", response.ptr);
  fprintf(stderr, "Validation:   %s\n", validation.ptr);

  free_string(&response);
  free_string(&validation);
  return 0;
}

void init_string(struct string *s) {
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

void free_string(struct string *s) {
  if (s) free(s->ptr);
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s) {
  size_t new_len = s->len + size*nmemb;
  s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size*nmemb;
}

// TODO maybe avoid boiler plate by
// 1. Get passed a char *
// 2. init a string in this function using that char *
// 3. Do the call
int fetch_url(const char* url, struct string *s) {
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if (!curl) {
    return -1;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);
  res = curl_easy_perform(curl);

  // always cleanup
  curl_easy_cleanup(curl);

  return res;
}

// TODO should this be done using a union instead?
unsigned char* pack64(long value) {
  int i;
  unsigned char *bytes = calloc(8, sizeof(unsigned char));

  for (i=0; i<8; i++) bytes[7-i] = value >> (8-1-i)*8;
  return bytes;
}

unsigned char *encode64(const unsigned char *input, int length) {
  BIO *b64, *mem;
  unsigned char* output;

  b64 = BIO_new(BIO_f_base64()); // create BIO to perform base64
  mem = BIO_new(BIO_s_mem()); // create BIO that holds the result
  mem = BIO_push(b64, mem);

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // force no newline
  BIO_write(b64, input, length);
  BIO_flush(b64);

  // get a pointer to mem's data
  BIO_get_mem_data(mem, &output);
  return output;
}

unsigned char* decode64(const unsigned char *input, int length) {
  BIO *b64, *mem;
  unsigned char *output = calloc(length, sizeof(unsigned char));

  b64 = BIO_new(BIO_f_base64());
  mem = BIO_new_mem_buf((unsigned char *)input, length);
  mem = BIO_push(b64, mem);

  BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
  BIO_read(mem, output, length);
  BIO_free_all(mem);

  return output;
}