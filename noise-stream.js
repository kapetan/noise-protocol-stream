var crypto = require('crypto')
var events = require('events')

var noise = require('./build/noise')
var functions = require('./src/functions')

var supported = (typeof WebAssembly === 'object')

var noop = function () {
  throw new Error('operation not supported')
}

module.exports = exports = supported ? function () {
  var that = new events.EventEmitter()
  var instance = noise({
    random_bytes: crypto.randomBytes,
    noise_stream_handshake_on_write: function (state, buf) {
      that.emit('noise_stream_handshake_write', state, buf)
    },
    noise_stream_handshake_on_read: function (state) {
      that.emit('noise_stream_handshake_read', state)
    },
    noise_stream_handshake_on_split: function (state, macSize, localPrivateKey, localPublicKey, remotePublicKey) {
      that.emit('noise_stream_handshake_split', state, macSize, localPrivateKey, localPublicKey, remotePublicKey)
    }
  })

  functions.forEach(function (name) {
    that[name.replace(/^_/, '')] = instance[name]
  })

  that.heap = instance.HEAPU8
  that.ready = false

  instance
    .then(function () {
      process.nextTick(function () {
        that.ready = true
        that.emit('ready')
      })
    })

  return that
} : function () {
  var that = new events.EventEmitter()

  functions.forEach(function (name) {
    that[name.replace(/^_/, '')] = noop
  })

  that.heap = null
  that.ready = false
  return that
}

exports.supported = supported
