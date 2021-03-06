#include <stdint.h>
#include <stddef.h>

#define ED25519_CUSTOMRANDOM
#define ED25519_REFHASH

typedef struct NoiseStreamState NoiseStreamState;

extern void noise_stream_handshake_on_write(NoiseStreamState *state, uint8_t *data, size_t size);
extern void noise_stream_handshake_on_read(NoiseStreamState *state);
extern void noise_stream_handshake_on_split(NoiseStreamState *state, size_t mac_size,
  uint8_t *local_private_key, size_t local_private_key_size,
  uint8_t *local_public_key, size_t local_public_key_size,
  uint8_t *remote_public_key, size_t remote_public_key_size);

extern void noise_rand_bytes(void *bytes, size_t size);

int noise_stream_new(
  NoiseStreamState **state,
  int initiator,
  uint8_t *prologue, size_t prologue_size,
  uint8_t *private_key, size_t private_key_size);
int noise_stream_initialize(NoiseStreamState *state);
int noise_stream_free(NoiseStreamState *state);
int noise_stream_handhshake_read(NoiseStreamState *state, uint8_t *data, size_t size);
int noise_stream_encrypt(NoiseStreamState *state, uint8_t *data, size_t size, size_t *out);
int noise_stream_decrypt(NoiseStreamState *state, uint8_t *data, size_t size, size_t *out);
