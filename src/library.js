mergeInto(LibraryManager.library, {
  noise_stream_handshake_on_write: function (state, ptr, size) {
    var buf = Buffer.from(HEAPU8.buffer, ptr, size)
    Module['noise_stream_handshake_on_write'](state, buf)
  },
  noise_stream_handshake_on_read: function (state) {
    Module['noise_stream_handshake_on_read'](state)
  },
  noise_stream_handshake_on_split: function (state, macSize) {
    Module['noise_stream_handshake_on_split'](state, macSize)
  },
  noise_rand_bytes: function (ptr, size) {
    var buf = Module['random_bytes'](size)
    if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf)
    buf.copy(HEAPU8, ptr, 0, size)
  }
});
