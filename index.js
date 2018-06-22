/* eslint-disable no-labels */

var util = require('util')
var through = require('through2')
var lpStream = require('length-prefixed-stream')
var Duplexify = require('duplexify')
var each = require('stream-each')
var eos = require('end-of-stream')

var noise = require('./noise-stream')

var PTR_SIZE = 4
var MESSAGE_SIZE = 65535

var lib = noise()
var heap = lib.heap

var createError = function (s, code) {
  return new Error(s + (code != null ? (' ' + code) : ''))
}

var pointer = function () {
  return lib.malloc(PTR_SIZE)
}

var dereference = function (ptr) {
  var buf = Buffer.from(heap.buffer, ptr, PTR_SIZE)
  return buf.readUInt32LE(0)
}

var copymem = function (src, srcOffset, ptr, size) {
  if (!Buffer.isBuffer(src)) src = Buffer.from(src)
  src = src.slice(srcOffset, srcOffset + size)
  heap.set(src, ptr)
}

var writemem = function (src) {
  if (!Buffer.isBuffer(src)) src = Buffer.from(src)
  var ptr = lib.malloc(src.length)
  if (ptr) heap.set(src, ptr)
  return ptr
}

var readmem = function (ptr, size, dest, destOffset) {
  var buf = heap.slice(ptr, ptr + size)
  if (!dest) dest = Buffer.from(buf)
  else dest.set(buf, destOffset || 0)
  return dest
}

var DecryptStream = function (options) {
  Duplexify.call(this)

  var self = this
  var decode = lpStream.decode()
  var pass = through()

  decode.on('end', function () {
    pass.end()
  })

  each(decode, function (data, next) {
    if (self.destroyed) return
    if (self._streamPtr) {
      self._writeOutput(data, next)
    } else if (self._handshakeCb) {
      var cb = self._handshakeCb
      self._handshakeCb = null
      cb(data)
      next()
    } else {
      self._inputData = data
      self._inputCb = next
    }
  })

  this._input = decode
  this._output = pass
  this._inputData = null
  this._inputCb = null
  this._handshakeCb = null
  this._streamPtr = null
  this._macSize = 0

  this.setWritable(decode)
  this.setReadable(pass)
}

util.inherits(DecryptStream, Duplexify)

DecryptStream.prototype._readHandshake = function (cb) {
  var ondrain = function (data, next) {
    cb(data)
    next()
  }

  if (this._inputData) this._drainInput(ondrain)
  else this._handshakeCb = cb
}

DecryptStream.prototype._splitHandshake = function (ptr, macSize) {
  this._streamPtr = ptr
  this._macSize = macSize
  if (this._inputData) this._drainInput(this._writeOutput.bind(this))
}

DecryptStream.prototype._drainInput = function (cb) {
  var data = this._inputData
  var next = this._inputCb
  this._inputData = this._inputCb = null
  cb(data, next)
}

DecryptStream.prototype._writeOutput = function (data, cb) {
  var n
  var dataPtr
  var buffer
  var dataOffset
  var dataSize
  var err

  n = Math.ceil(data.length / MESSAGE_SIZE)
  dataPtr = writemem(data)

  if (dataPtr) {
    buffer = Buffer.alloc(data.length - n * this._macSize)

    error: {
      for (var i = 0; i < n; i++) {
        dataOffset = dataPtr + i * MESSAGE_SIZE
        dataSize = i === (n - 1)
          ? (data.length - (n - 1) * MESSAGE_SIZE)
          : MESSAGE_SIZE

        err = lib.noise_stream_decrypt(this._streamPtr, dataOffset, dataSize, 0)

        if (!err) {
          readmem(dataOffset, dataSize - this._macSize, buffer, i * (MESSAGE_SIZE - this._macSize))
        } else {
          cb(createError('noise_stream_decrypt', err))
          break error
        }
      }

      this._output.write(buffer, cb)
    }

    lib.free(dataPtr)
  } else {
    cb(createError('malloc'))
  }
}

var EncryptStream = function (options) {
  Duplexify.call(this)

  var pass = through()
  var encode = lpStream.encode()

  pass.on('end', function () {
    encode.end()
  })

  this._input = pass
  this._output = encode

  this.setWritable(pass)
  this.setReadable(encode)
}

util.inherits(EncryptStream, Duplexify)

EncryptStream.prototype._writeHandshake = function (data) {
  this._output.write(data)
}

EncryptStream.prototype._splitHandshake = function (ptr, macSize) {
  var self = this

  each(this._input, function (data, next) {
    if (self.destroyed) return

    var n
    var totalSize
    var dataPtr
    var dataOffset
    var dataSize
    var err

    n = Math.ceil(data.length / (MESSAGE_SIZE - macSize))
    totalSize = data.length + n * macSize
    dataPtr = lib.malloc(totalSize)

    if (dataPtr) {
      error: {
        for (var i = 0; i < n; i++) {
          dataOffset = dataPtr + i * MESSAGE_SIZE
          dataSize = i === (n - 1)
            ? (data.length - (n - 1) * (MESSAGE_SIZE - macSize))
            : (MESSAGE_SIZE - macSize)

          copymem(data, i * (MESSAGE_SIZE - macSize), dataOffset, dataSize)

          err = lib.noise_stream_encrypt(ptr, dataOffset, dataSize, 0)

          if (err) {
            next(createError('noise_stream_encrypt', err))
            break error
          }
        }

        self._output.write(readmem(dataPtr, totalSize), next)
      }

      lib.free(dataPtr)
    } else {
      next(createError('malloc'))
    }
  })
}

module.exports = exports = function (options) {
  if (!options) options = {}

  var streamPtr = null
  var ended = false
  var split = false
  var decrypt = new DecryptStream()
  var encrypt = new EncryptStream()

  var onready = function () {
    var err
    var streamPtrPtr
    var prologuePtr
    var privateKeyPtr

    streamPtrPtr = pointer()

    if (streamPtrPtr) {
      if (options.prologue != null) prologuePtr = writemem(options.prologue)
      if (options.prologue == null || prologuePtr) {
        if (options.privateKey != null) privateKeyPtr = writemem(options.privateKey)
        if (options.privateKey == null || privateKeyPtr) {
          err = lib.noise_stream_new(
            streamPtrPtr,
            options.initiator ? 1 : 0,
            prologuePtr,
            prologuePtr ? Buffer.byteLength(options.prologue) : 0,
            privateKeyPtr,
            privateKeyPtr ? Buffer.byteLength(options.privateKey) : 0)

          if (!err) {
            streamPtr = dereference(streamPtrPtr)
            err = lib.noise_stream_initialize(streamPtr)
            if (err) destroy('noise_stream_initialize', err)
          } else {
            destroy('noise_stream_new', err)
          }

          if (privateKeyPtr) lib.free(privateKeyPtr)
        } else {
          destroy('malloc')
        }

        if (prologuePtr) lib.free(prologuePtr)
      } else {
        destroy('malloc')
      }

      lib.free(streamPtrPtr)
    } else {
      destroy('malloc')
    }
  }

  var onhandshakewrite = function (ptr, buf) {
    if (ptr === streamPtr) encrypt._writeHandshake(buf)
  }

  var onhandshakeread = function (ptr) {
    if (ptr === streamPtr) {
      decrypt._readHandshake(function (buf) {
        var bufPtr
        var err

        bufPtr = writemem(buf)

        if (bufPtr) {
          err = lib.noise_stream_handhshake_read(ptr, bufPtr, buf.length)
          if (err) destroy('noise_stream_handhshake_read', err)
          lib.free(bufPtr)
        } else {
          destroy('malloc')
        }
      })
    }
  }

  var onhandshakesplit = function (ptr, macSize, localPrivateKey, localPublicKey, remotePublicKey) {
    if (ptr === streamPtr) {
      var onverify = function (err, accept) {
        if (!err && accept === true) {
          decrypt._splitHandshake(ptr, macSize)
          encrypt._splitHandshake(ptr, macSize)
          split = true
          decrypt.emit('handshake', localPrivateKey, localPublicKey, remotePublicKey)
          encrypt.emit('handshake', localPrivateKey, localPublicKey, remotePublicKey)
        } else {
          decrypt.destroy(err)
          encrypt.destroy(err)
        }
      }

      if (options.verify) options.verify(localPrivateKey, localPublicKey, remotePublicKey, onverify)
      else onverify(null, true)
    }
  }

  var cleanup = function () {
    if (!ended && split) {
      ended = true
      return
    }

    lib.removeListener('ready', onready)
    lib.removeListener('noise_stream_handshake_write', onhandshakewrite)
    lib.removeListener('noise_stream_handshake_read', onhandshakeread)
    lib.removeListener('noise_stream_handshake_split', onhandshakesplit)
    if (streamPtr) lib.noise_stream_free(streamPtr)
    streamPtr = null
  }

  var destroy = function (s, code) {
    var err = createError(s, code)
    decrypt.destroy(err)
    encrypt.destroy(err)
  }

  lib.on('noise_stream_handshake_write', onhandshakewrite)
  lib.on('noise_stream_handshake_read', onhandshakeread)
  lib.on('noise_stream_handshake_split', onhandshakesplit)

  eos(decrypt, { error: false }, cleanup)
  eos(encrypt, { error: false }, cleanup)

  if (lib.ready) process.nextTick(onready)
  else lib.once('ready', onready)
  return { decrypt, encrypt }
}

exports.supported = noise.supported
