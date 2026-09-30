// SPDX-License-Identifier: GPL-3.0-or-later
#include "plank_admission.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(PLANK_ADMISSION_OPENSSL)
#include <openssl/evp.h>
#else
#include <Security/Security.h>
/* macOS 27 exports these Ed25519 symbols from Security.framework without
 * declaring them in the public SecKey.h that ships with that SDK. */
extern const CFStringRef kSecAttrKeyTypeEd25519;
extern const SecKeyAlgorithm kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512;
#endif

static void set_reason(plank_admission_decision *decision, const char *reason) {
  snprintf(decision->reason, sizeof decision->reason, "%s", reason);
}

static int token_char(unsigned char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

static int copy_token(char *out, size_t cap, const uint8_t *bytes, size_t len, size_t min_len) {
  if (len < min_len || len >= cap) return 0;
  for (size_t i = 0; i < len; ++i) {
    if (!token_char(bytes[i])) return 0;
  }
  memcpy(out, bytes, len);
  out[len] = 0;
  return 1;
}

static int lowercase_uuid(char *out, const uint8_t *bytes, size_t len) {
  static const int hyphens[] = {8, 13, 18, 23};
  if (len != 36) return 0;
  for (size_t i = 0; i < 36; ++i) {
    int hyphen = 0;
    for (size_t h = 0; h < 4; ++h) hyphen |= ((int) i == hyphens[h]);
    if (hyphen) {
      if (bytes[i] != '-') return 0;
    } else if (!((bytes[i] >= '0' && bytes[i] <= '9') || (bytes[i] >= 'a' && bytes[i] <= 'f'))) {
      return 0;
    }
  }
  memcpy(out, bytes, 36);
  out[36] = 0;
  return 1;
}

static int ascii_unix(char *out, const uint8_t *bytes, size_t len, int64_t *value) {
  if (len == 0 || len > 20) return 0;
  if (bytes[0] == '0' && len != 1) return 0;
  int64_t parsed = 0;
  for (size_t i = 0; i < len; ++i) {
    if (bytes[i] < '0' || bytes[i] > '9') return 0;
    if (parsed > (INT64_MAX - (bytes[i] - '0')) / 10) return 0;
    parsed = parsed * 10 + (bytes[i] - '0');
  }
  memcpy(out, bytes, len);
  out[len] = 0;
  *value = parsed;
  return 1;
}

static int take_field(const uint8_t **cursor, const uint8_t *end, const uint8_t **data, size_t *len) {
  if (*cursor + 2 > end) return 0;
  size_t n = ((size_t) (*cursor)[0] << 8) | (*cursor)[1];
  *cursor += 2;
  if (n > (size_t) (end - *cursor)) return 0;
  *data = *cursor;
  *len = n;
  *cursor += n;
  return 1;
}

static int put_field(uint8_t **cursor, uint8_t *end, const char *text) {
  size_t n = strlen(text);
  if (n > 65535 || *cursor + 2 + n > end) return 0;
  (*cursor)[0] = (uint8_t) (n >> 8);
  (*cursor)[1] = (uint8_t) n;
  *cursor += 2;
  memcpy(*cursor, text, n);
  *cursor += n;
  return 1;
}

int plank_admission_encode(const plank_admission_fields *fields, uint8_t *out, size_t cap, size_t *out_len) {
  if (!fields || !out || cap < 5 || !out_len) return 0;
  uint8_t *cursor = out;
  uint8_t *end = out + cap;
  memcpy(cursor, "PLAD", 4);
  cursor[4] = 1;
  cursor += 5;
  if (!put_field(&cursor, end, fields->issuer) || !put_field(&cursor, end, fields->key_id) ||
      !put_field(&cursor, end, fields->admission_id) || !put_field(&cursor, end, fields->subject) ||
      !put_field(&cursor, end, fields->workstation_uniqueid) || !put_field(&cursor, end, fields->issued_at) ||
      !put_field(&cursor, end, fields->expires_at) || !put_field(&cursor, end, fields->audience) ||
      !put_field(&cursor, end, fields->purpose)) return 0;
  *out_len = (size_t) (cursor - out);
  return *out_len <= PLANK_ADMISSION_PAYLOAD_MAX;
}

static const char b64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int plank_admission_b64url_encode(const uint8_t *in, size_t len, char *out, size_t cap) {
  size_t need = 4 * ((len + 2) / 3);
  if (len % 3) need -= 3 - (len % 3);
  if (!out || cap < need + 1) return 0;
  size_t o = 0;
  for (size_t i = 0; i < len; i += 3) {
    unsigned value = (unsigned) in[i] << 16;
    if (i + 1 < len) value |= (unsigned) in[i + 1] << 8;
    if (i + 2 < len) value |= in[i + 2];
    out[o++] = b64url[(value >> 18) & 63];
    out[o++] = b64url[(value >> 12) & 63];
    if (i + 1 < len) out[o++] = b64url[(value >> 6) & 63];
    if (i + 2 < len) out[o++] = b64url[value & 63];
  }
  out[o] = 0;
  return 1;
}

static int b64url_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

int plank_admission_b64url_decode(const char *in, uint8_t *out, size_t cap, size_t *out_len) {
  if (!in || !out || !out_len) return 0;
  size_t len = strlen(in);
  if (len == 0 || strchr(in, '+') || strchr(in, '/') || strchr(in, '=')) return 0;
  size_t o = 0;
  unsigned value = 0;
  int bits = 0;
  for (size_t i = 0; i < len; ++i) {
    int digit = b64url_value(in[i]);
    if (digit < 0) return 0;
    value = (value << 6) | (unsigned) digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= cap) return 0;
      out[o++] = (uint8_t) ((value >> bits) & 0xff);
    }
  }
  if (bits >= 6) return 0;
  *out_len = o;
  return 1;
}

int plank_admission_ed25519_verify(const uint8_t public_key[32], const uint8_t *message, size_t message_len, const uint8_t signature[64]) {
  if (!public_key || !message || !signature) return 0;
#if defined(PLANK_ADMISSION_OPENSSL)
  EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
  if (!key) return 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
      EVP_DigestVerify(ctx, signature, 64, message, message_len) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok;
#else
  CFDataRef key_data = CFDataCreate(NULL, public_key, 32);
  CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(NULL, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeEd25519);
  CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPublic);
  CFErrorRef error = NULL;
  SecKeyRef key = SecKeyCreateWithData(key_data, attrs, &error);
  if (error) CFRelease(error);
  CFRelease(key_data);
  CFRelease(attrs);
  if (!key) return 0;
  CFDataRef message_data = CFDataCreate(NULL, message, (CFIndex) message_len);
  CFDataRef signature_data = CFDataCreate(NULL, signature, 64);
  error = NULL;
  Boolean ok = SecKeyVerifySignature(key, kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512, message_data, signature_data, &error);
  if (error) CFRelease(error);
  CFRelease(message_data);
  CFRelease(signature_data);
  CFRelease(key);
  return ok ? 1 : 0;
#endif
}

int plank_admission_parse_trust_token(const char *token, plank_admission_key *out) {
  if (!token || !out) return 0;
  const char *first = strchr(token, '|');
  const char *second = first ? strchr(first + 1, '|') : NULL;
  if (!first || !second || strchr(second + 1, '|')) return 0;
  size_t key_len = (size_t) (first - token);
  size_t issuer_len = (size_t) (second - first - 1);
  uint8_t raw[32];
  size_t raw_len = 0;
  if (!copy_token(out->key_id, sizeof out->key_id, (const uint8_t *) token, key_len, 1) ||
      !copy_token(out->issuer, sizeof out->issuer, (const uint8_t *) (first + 1), issuer_len, 1) ||
      !plank_admission_b64url_decode(second + 1, raw, sizeof raw, &raw_len) || raw_len != 32) return 0;
  memcpy(out->public_key, raw, 32);
  return 1;
}

int plank_admission_uniqueid_matches(const char *expected, const char *actual) {
  return expected && actual && expected[0] && strcmp(expected, actual) == 0;
}

static int parse_payload(const uint8_t *payload, size_t len, plank_admission_fields *fields, int64_t *issued, int64_t *expires) {
  if (len < 5 || len > PLANK_ADMISSION_PAYLOAD_MAX || memcmp(payload, "PLAD", 4) != 0 || payload[4] != 1) return 0;
  const uint8_t *cursor = payload + 5;
  const uint8_t *end = payload + len;
  const uint8_t *data = NULL;
  size_t n = 0;
  memset(fields, 0, sizeof *fields);
  if (!take_field(&cursor, end, &data, &n) || !copy_token(fields->issuer, sizeof fields->issuer, data, n, 1)) return 0;
  if (!take_field(&cursor, end, &data, &n) || !copy_token(fields->key_id, sizeof fields->key_id, data, n, 1)) return 0;
  if (!take_field(&cursor, end, &data, &n) || !lowercase_uuid(fields->admission_id, data, n)) return 0;
  if (!take_field(&cursor, end, &data, &n) || n < 1 || n > PLANK_ADMISSION_SUBJECT_MAX) return 0;
  if (memchr(data, 0, n) || memchr(data, '\n', n) || memchr(data, '\r', n)) return 0;
  memcpy(fields->subject, data, n);
  if (!take_field(&cursor, end, &data, &n) || !lowercase_uuid(fields->workstation_uniqueid, data, n)) return 0;
  if (!take_field(&cursor, end, &data, &n) || !ascii_unix(fields->issued_at, data, n, issued)) return 0;
  if (!take_field(&cursor, end, &data, &n) || !ascii_unix(fields->expires_at, data, n, expires)) return 0;
  if (!take_field(&cursor, end, &data, &n) || n < 1 || n >= sizeof fields->audience) return 0;
  memcpy(fields->audience, data, n);
  if (!take_field(&cursor, end, &data, &n) || n < 1 || n >= sizeof fields->purpose) return 0;
  memcpy(fields->purpose, data, n);
  return cursor == end;
}

static void purge_expired(int dirfd, int64_t now, int64_t skew) {
  int dupfd = dup(dirfd);
  if (dupfd < 0) return;
  DIR *dir = fdopendir(dupfd);
  if (!dir) {
    close(dupfd);
    return;
  }
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.') continue;
    char id[37];
    if (!lowercase_uuid(id, (const uint8_t *) entry->d_name, strlen(entry->d_name))) continue;
    int fd = openat(dirfd, entry->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) continue;
    char buf[64];
    ssize_t got = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (got <= 0) continue;
    buf[got] = 0;
    char *newline = strchr(buf, '\n');
    if (newline) *newline = 0;
    int64_t expires = 0;
    char expiry[21];
    if (!ascii_unix(expiry, (const uint8_t *) buf, strlen(buf), &expires)) continue;
    if (expires > INT64_MAX - skew) continue;
    if (expires + skew < now) unlinkat(dirfd, entry->d_name, 0);
  }
  closedir(dir);
}

static int consume_id(const char *dir, const char *admission_id, int64_t expires, const char *key_id, int64_t now, int64_t skew) {
  if (!dir || !dir[0]) return -1;
  if (mkdir(dir, 0700) != 0 && errno != EEXIST) return -1;
  int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dirfd < 0) return -1;
  fchmod(dirfd, 0700);
  purge_expired(dirfd, now, skew);
  int fd = openat(dirfd, admission_id, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    int err = errno;
    close(dirfd);
    return err == EEXIST ? 0 : -1;
  }
  char body[160];
  int n = snprintf(body, sizeof body, "%lld\n%s\n", (long long) expires, key_id);
  int ok = n > 0 && n < (int) sizeof body && write(fd, body, (size_t) n) == n;
  if (ok) {
    fchmod(fd, 0600);
    fsync(fd);
  }
  close(fd);
  if (!ok) unlinkat(dirfd, admission_id, 0);
  else fsync(dirfd);
  close(dirfd);
  return ok ? 1 : -1;
}

static const plank_admission_key *find_key(const plank_admission_key *keys, size_t key_count, const char *key_id) {
  if (!keys) return NULL;
  for (size_t i = 0; i < key_count; ++i) {
    if (strcmp(keys[i].key_id, key_id) == 0) return &keys[i];
  }
  return NULL;
}

void plank_admission_authorize(
    int require,
    int config_valid,
    int presented,
    int wrapper_version,
    const char *payload_b64,
    const char *signature_b64,
    const plank_admission_key *keys,
    size_t key_count,
    const char *local_uniqueid,
    int64_t now_unix,
    int64_t max_ttl,
    int64_t skew,
    const char *consume_dir,
    plank_admission_decision *decision) {
  memset(decision, 0, sizeof *decision);
  if (!require) {
    decision->status = PLANK_ADMISSION_STATUS_SKIP;
    set_reason(decision, "not_required");
    return;
  }
  if (!config_valid || !keys || key_count == 0 || key_count > PLANK_ADMISSION_KEYS_MAX || max_ttl <= 0 || skew < 0) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "config_invalid");
    return;
  }
  if (!presented || !payload_b64 || !signature_b64) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "malformed");
    return;
  }
  uint8_t payload[PLANK_ADMISSION_PAYLOAD_MAX];
  uint8_t signature[64];
  size_t payload_len = 0;
  size_t signature_len = 0;
  if (!plank_admission_b64url_decode(payload_b64, payload, sizeof payload, &payload_len) ||
      !plank_admission_b64url_decode(signature_b64, signature, sizeof signature, &signature_len) ||
      signature_len != 64 || payload_len == 0 || payload_len > PLANK_ADMISSION_PAYLOAD_MAX) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "malformed");
    return;
  }
  plank_admission_fields fields;
  int64_t issued = 0;
  int64_t expires = 0;
  if (!parse_payload(payload, payload_len, &fields, &issued, &expires) || wrapper_version != 1) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "malformed");
    return;
  }
  snprintf(decision->admission_id, sizeof decision->admission_id, "%s", fields.admission_id);
  snprintf(decision->key_id, sizeof decision->key_id, "%s", fields.key_id);
  const plank_admission_key *key = find_key(keys, key_count, fields.key_id);
  if (!key) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "unknown_key_id");
    return;
  }
  if (!plank_admission_ed25519_verify(key->public_key, payload, payload_len, signature)) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "bad_signature");
    return;
  }
  if (strcmp(fields.issuer, key->issuer) != 0) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "issuer_not_allowed");
    return;
  }
  if (strcmp(fields.audience, "plank-host") != 0) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "wrong_audience");
    return;
  }
  if (strcmp(fields.purpose, "connect-attempt") != 0) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "wrong_purpose");
    return;
  }
  if (!local_uniqueid || strcmp(fields.workstation_uniqueid, local_uniqueid) != 0) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "wrong_uniqueid");
    return;
  }
  if (!(expires > issued)) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "malformed");
    return;
  }
  if (expires - issued > max_ttl) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "excessive_ttl");
    return;
  }
  if (now_unix > INT64_MAX - skew || now_unix + skew < issued) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "not_yet_valid");
    return;
  }
  if (now_unix >= skew && now_unix - skew > expires) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "expired");
    return;
  }
  int consumed = consume_id(consume_dir, fields.admission_id, expires, fields.key_id, now_unix, skew);
  if (consumed == 0) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "replay");
    return;
  }
  if (consumed != 1) {
    decision->status = PLANK_ADMISSION_STATUS_REJECT;
    set_reason(decision, "store_error");
    return;
  }
  decision->status = PLANK_ADMISSION_STATUS_ACCEPT;
  set_reason(decision, "accepted");
}
