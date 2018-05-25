#include <stdlib.h>
#include <noise/protocol.h>
#include "noise-stream.h"

struct NoiseStreamState {
  NoiseHandshakeState *handshake;
  NoiseCipherState *send_cipher;
  NoiseCipherState *recv_cipher;
};

static uint8_t data[4096];

static int noise_stream_process_action(NoiseStreamState *state) {
  int err;
  NoiseBuffer buf;
  NoiseCipherState *send_cipher;
  NoiseCipherState *recv_cipher;
  int action = noise_handshakestate_get_action(state->handshake);

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
      err = noise_handshakestate_split(state->handshake, &send_cipher, &recv_cipher);
      if (err != NOISE_ERROR_NONE) return err;
      noise_handshakestate_free(state->handshake);
      state->handshake = NULL;
      state->send_cipher = send_cipher;
      state->recv_cipher = recv_cipher;
      noise_stream_handshake_on_split(state, noise_cipherstate_get_mac_length(send_cipher));
      return NOISE_ERROR_NONE;
    default:
      return NOISE_ERROR_SYSTEM;
  }
}

int noise_stream_new(NoiseStreamState **state, int initiator) {
  int err;
  NoiseHandshakeState *handshake;

  *state = (NoiseStreamState *) malloc(sizeof(NoiseStreamState));
  if (!(*state)) return NOISE_ERROR_NO_MEMORY;

  err = noise_handshakestate_new_by_name(&handshake, "Noise_NN_25519_AESGCM_SHA256",
    initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER);
  if (err != NOISE_ERROR_NONE) return err;

  err = noise_handshakestate_start(handshake);
  if (err != NOISE_ERROR_NONE) return err;

  (*state)->handshake = handshake;
  (*state)->send_cipher = NULL;
  (*state)->recv_cipher = NULL;

  return NOISE_ERROR_NONE;
}

int noise_stream_initialize(NoiseStreamState *state) {
  return noise_stream_process_action(state);
}

int noise_stream_free(NoiseStreamState *state) {
  if (state->handshake) noise_handshakestate_free(state->handshake);
  if (state->send_cipher) noise_cipherstate_free(state->send_cipher);
  if (state->recv_cipher) noise_cipherstate_free(state->recv_cipher);
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
  err = noise_cipherstate_decrypt(state->recv_cipher, &buf);
  if (err != NOISE_ERROR_NONE) return err;
  *out = buf.size;
  return NOISE_ERROR_NONE;
}

int noise_stream_encrypt(NoiseStreamState *state, uint8_t *data, size_t size, size_t *out) {
  int err;
  NoiseBuffer buf;

  noise_buffer_set_inout(buf, data, size, size + noise_cipherstate_get_mac_length(state->send_cipher));
  err = noise_cipherstate_encrypt(state->send_cipher, &buf);
  if (err != NOISE_ERROR_NONE) return err;
  *out = buf.size;
  return NOISE_ERROR_NONE;
}
