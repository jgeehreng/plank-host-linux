// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version-1 broker admission. key_id selects a pinned Ed25519 public key.
 * The public key is never stored inside key_id. */

enum {
  PLANK_ADMISSION_STATUS_SKIP = 0,
  PLANK_ADMISSION_STATUS_ACCEPT = 1,
  PLANK_ADMISSION_STATUS_REJECT = 2,
  PLANK_ADMISSION_KEY_ID_MAX = 64,
  PLANK_ADMISSION_ISSUER_MAX = 64,
  PLANK_ADMISSION_SUBJECT_MAX = 256,
  PLANK_ADMISSION_PAYLOAD_MAX = 1024,
  PLANK_ADMISSION_KEYS_MAX = 8
};

typedef struct plank_admission_key {
  char key_id[PLANK_ADMISSION_KEY_ID_MAX + 1];
  char issuer[PLANK_ADMISSION_ISSUER_MAX + 1];
  uint8_t public_key[32];
} plank_admission_key;

typedef struct plank_admission_fields {
  char issuer[PLANK_ADMISSION_ISSUER_MAX + 1];
  char key_id[PLANK_ADMISSION_KEY_ID_MAX + 1];
  char admission_id[37];
  char subject[PLANK_ADMISSION_SUBJECT_MAX + 1];
  char workstation_uniqueid[37];
  char issued_at[21];
  char expires_at[21];
  char audience[11];
  char purpose[16];
} plank_admission_fields;

typedef struct plank_admission_decision {
  int status;
  char reason[32];
  char admission_id[37];
  char key_id[PLANK_ADMISSION_KEY_ID_MAX + 1];
} plank_admission_decision;

/* Single encoder. Hosts verify these exact bytes; they do not reserialize. */
int plank_admission_encode(const plank_admission_fields *fields, uint8_t *out, size_t cap, size_t *out_len);

int plank_admission_b64url_encode(const uint8_t *in, size_t len, char *out, size_t cap);
int plank_admission_b64url_decode(const char *in, uint8_t *out, size_t cap, size_t *out_len);

int plank_admission_ed25519_verify(const uint8_t public_key[32], const uint8_t *message, size_t message_len, const uint8_t signature[64]);

int plank_admission_parse_trust_token(const char *token, plank_admission_key *out);

int plank_admission_uniqueid_matches(const char *expected, const char *actual);

/* require=0 ignores a presented ticket and does not touch the consume-set.
 * On ACCEPT the admission_id has been atomically inserted under consume_dir.
 * now_unix, max_ttl, and skew are seconds. skew may be 0. max_ttl must be > 0
 * when require is set. config_valid is 0 when trust material is missing. */
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
    plank_admission_decision *decision);

#ifdef __cplusplus
}
#endif
