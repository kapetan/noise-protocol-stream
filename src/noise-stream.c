#include <stdlib.h>
#include <noise/protocol.h>
#include "noise-stream.h"

struct NoiseStreamState {
  NoiseHandshakeState *handshake;
  NoiseCipherState *encrypt_cipher;
  NoiseCipherState *decrypt_cipher;
};

static uint8_t data[1024];

static int noise_stream_process_action(NoiseStreamState *state) {
  int err;
  NoiseBuffer buf;
  NoiseDHState *local_dh;
  NoiseDHState *remote_dh;
  NoiseCipherState *encrypt_cipher;
  NoiseCipherState *decrypt_cipher;
  size_t local_private_key_size;
  size_t local_public_key_size;
  size_t remote_public_key_size;
  int action;

  action = noise_handshakestate_get_action(state->handshake);

  switch (action) {
    case NOISE_ACTION_WRITE_MESSAGE:
      noise_buffer_set_output(buf, data, sizeof(data));
      err = noise_handshakestate_write_message(state->handshake, &buf, NULL);
      if (err != NOISE_ERROR_NONE) return err;
      noise_stream_handshake_on_write(state, buf.data, buf.size);
      return noise_stream_process_action(state);
    case NOISE_ACTION_READ_MESSAGE:
      noise_stream_handshake_on_read(state);
      return NOISE_ERROR_NONE;
    case NOISE_ACTION_SPLIT:
      err = noise_handshakestate_split(state->handshake, &encrypt_cipher, &decrypt_cipher);
      if (err != NOISE_ERROR_NONE) return err;

      local_dh = noise_handshakestate_get_local_keypair_dh(state->handshake);
      local_private_key_size = noise_dhstate_get_private_key_length(local_dh);
      local_public_key_size = noise_dhstate_get_public_key_length(local_dh);

      err = noise_dhstate_get_keypair(local_dh,
        data, local_private_key_size,
        data + local_private_key_size, local_public_key_size);
      if (err != NOISE_ERROR_NONE) return err;

      remote_dh = noise_handshakestate_get_remote_public_key_dh(state->handshake);
      remote_public_key_size = noise_dhstate_get_public_key_length(remote_dh);

      err = noise_dhstate_get_public_key(remote_dh,
        data + local_private_key_size + local_public_key_size, remote_public_key_size);

      noise_handshakestate_free(state->handshake);
      state->handshake = NULL;
      state->encrypt_cipher = encrypt_cipher;
      state->decrypt_cipher = decrypt_cipher;

      noise_stream_handshake_on_split(state, noise_cipherstate_get_mac_length(encrypt_cipher),
        data, local_private_key_size,
        data + local_private_key_size, local_public_key_size,
        data + local_private_key_size + local_public_key_size, remote_public_key_size);
      return NOISE_ERROR_NONE;
    default:
      return NOISE_ERROR_SYSTEM;
  }
}

int noise_stream_new(
    NoiseStreamState **state,
    int initiator,
    uint8_t *prologue, size_t prologue_size,
    uint8_t *private_key, size_t private_key_size) {

  int err;
  NoiseHandshakeState *handshake;
  NoiseDHState *dh;

  err = NOISE_ERROR_NONE;
  handshake = NULL;

  *state = (NoiseStreamState *) malloc(sizeof(NoiseStreamState));
  if (!(*state)) {
    err = NOISE_ERROR_NO_MEMORY;
    goto error;
  }

  err = noise_handshakestate_new_by_name(&handshake, "Noise_XX_25519_AESGCM_SHA256",
    initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER);
  if (err != NOISE_ERROR_NONE) goto error;

  if (prologue) {
    err = noise_handshakestate_set_prologue(handshake, prologue, prologue_size);
    if (err != NOISE_ERROR_NONE) goto error;
  }

  dh = noise_handshakestate_get_local_keypair_dh(handshake);

  if (private_key) err = noise_dhstate_set_keypair_private(dh, private_key, private_key_size);
  else err = noise_dhstate_generate_keypair(dh);

  if (err != NOISE_ERROR_NONE) goto error;

  err = noise_handshakestate_start(handshake);
  if (err != NOISE_ERROR_NONE) goto error;

  (*state)->handshake = handshake;
  (*state)->encrypt_cipher = NULL;
  (*state)->decrypt_cipher = NULL;

  goto out;

  error:
  if (*state) free(*state);
  if (handshake) noise_handshakestate_free(handshake);

  out:
  return err;
}

int noise_stream_initialize(NoiseStreamState *state) {
  return noise_stream_process_action(state);
}

int noise_stream_free(NoiseStreamState *state) {
  if (state->handshake) noise_handshakestate_free(state->handshake);
  if (state->encrypt_cipher) noise_cipherstate_free(state->encrypt_cipher);
  if (state->decrypt_cipher) noise_cipherstate_free(state->decrypt_cipher);
  free(state);
  return NOISE_ERROR_NONE;
}

int noise_stream_handhshake_read(NoiseStreamState *state, uint8_t *data, size_t size) {
  int err;
  NoiseBuffer buf;

  noise_buffer_set_input(buf, data, size);
  err = noise_handshakestate_read_message(state->handshake, &buf, NULL);
  if (err != NOISE_ERROR_NONE) return err;
  return noise_stream_process_action(state);
}

int noise_stream_decrypt(NoiseStreamState *state, uint8_t *data, size_t size, size_t *out) {
  int err;
  NoiseBuffer buf;

  noise_buffer_set_input(buf, data, size);
  err = noise_cipherstate_decrypt(state->decrypt_cipher, &buf);
  if (err != NOISE_ERROR_NONE) return err;
  if (out) *out = buf.size;
  return NOISE_ERROR_NONE;
}

int noise_stream_encrypt(NoiseStreamState *state, uint8_t *data, size_t size, size_t *out) {
  int err;
  NoiseBuffer buf;

  noise_buffer_set_inout(buf, data, size, size + noise_cipherstate_get_mac_length(state->encrypt_cipher));
  err = noise_cipherstate_encrypt(state->encrypt_cipher, &buf);
  if (err != NOISE_ERROR_NONE) return err;
  if (out) *out = buf.size;
  return NOISE_ERROR_NONE;
}
