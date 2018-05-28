/* global mergeInto, LibraryManager, HEAPU8, Module */

mergeInto(LibraryManager.library, {
  noise_stream_handshake_on_write: function (state, ptr, size) {
    Module['noise_stream_handshake_on_write'](state, Module['readMemory'](ptr, size))
  },
  noise_stream_handshake_on_read: function (state) {
    Module['noise_stream_handshake_on_read'](state)
  },
  noise_stream_handshake_on_split: function (state, macSize,
    localPrivateKeyPtr, localPrivateKeySize,
    localPublicKeyPtr, localPublicKeySize,
    remotePublicKeyPtr, remotePublicKeySize) {
    Module['noise_stream_handshake_on_split'](state, macSize,
      Module['readMemory'](localPrivateKeyPtr, localPrivateKeySize),
      Module['readMemory'](localPublicKeyPtr, localPublicKeySize),
      Module['readMemory'](remotePublicKeyPtr, remotePublicKeySize))
  },
  noise_rand_bytes: function (ptr, size) {
    var buf = Module['random_bytes'](size)
    if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf)
    HEAPU8.set(buf, ptr)
  }
})
