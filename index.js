var util = require('util')
var stream = require('stream')
var lpStream = require('length-prefixed-stream')
var Duplexify = require('duplexify')
var each = require('stream-each')
var eos = require('end-of-stream')

var noise = require('./noise-stream')

var PTR_SIZE = 4

var lib = noise()
var heap = lib.heap

var pointer = function () {
  return lib.malloc(PTR_SIZE)
}

var dereference = function (ptr) {
  var buf = Buffer.from(heap.buffer, ptr, PTR_SIZE)
  return buf.readUInt32LE(0)
}

var writemem = function (src, size) {
  if (!Buffer.isBuffer(src)) src = Buffer.from(src)
  if (!size) size = src.length
  var ptr = lib.malloc(size)
  src.copy(heap, ptr, 0, src.length)
  return ptr
}

var readmem = function (ptr, size) {
  var buf = heap.slice(ptr, ptr + size)
  return Buffer.from(buf)
}

var DecryptStream = function (options) {
  Duplexify.call(this)

  var self = this
  var decode = lpStream.decode()
  var pass = new stream.PassThrough()

  decode.on('finish', function () {
    pass.end()
  })

  each(decode, function (data, next) {
    if (self._streamPtr) {
      var dataPtr = writemem(data)
      var sizePtr = pointer()

      var err = lib.noise_stream_decrypt(self._streamPtr, dataPtr, data.length, sizePtr)
      if (err) return self.destroy(new Error('noise_stream_decrypt ' + err))
      var size = dereference(sizePtr)
      pass.write(readmem(dataPtr, size), next)

      lib.free(dataPtr)
      lib.free(sizePtr)
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

DecryptStream.prototype._splitHandshake = function (ptr) {
  this._streamPtr = ptr

  var self = this
  var ondrain = function (data, next) {
    self._output.write(data, next)
  }

  if (this._inputData) this._drainInput(ondrain)
}

DecryptStream.prototype._drainInput = function (cb) {
  var data = this._inputData
  var next = this._inputCb
  this._inputData = this._inputCb = null
  cb(data, next)
}

var EncryptStream = function (options) {
  Duplexify.call(this)

  var pass = new stream.PassThrough()
  var encode = lpStream.encode()

  pass.on('finish', function () {
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
    var dataPtr = writemem(data, data.length + macSize)
    var sizePtr = pointer()

    var err = lib.noise_stream_encrypt(ptr, dataPtr, data.length, sizePtr)
    if (err) return self.destroy(new Error('noise_stream_encrypt ' + err))
    var size = dereference(sizePtr)
    self._output.write(readmem(dataPtr, size), next)

    lib.free(dataPtr)
    lib.free(sizePtr)
  })
}

module.exports = function (options) {
  if (!options) options = {}

  var streamPtr = null
  var ended = false
  var decrypt = new DecryptStream()
  var encrypt = new EncryptStream()

  var onready = function () {
    var err = null
    var streamPtrPtr = pointer()

    err = lib.noise_stream_new(streamPtrPtr, options.initiator ? 1 : 0)
    if (err) return destroy('noise_stream_new', err)

    streamPtr = dereference(streamPtrPtr)
    lib.free(streamPtrPtr)

    err = lib.noise_stream_initialize(streamPtr)
    if (err) return destroy('noise_stream_initialize', err)
  }

  var onhandshakewrite = function (ptr, buf) {
    if (ptr === streamPtr) encrypt._writeHandshake(buf)
  }

  var onhandshakeread = function (ptr) {
    if (ptr === streamPtr) {
      decrypt._readHandshake(function (buf) {
        var bufPtr = writemem(buf)
        var err = lib.noise_stream_handhshake_read(ptr, bufPtr, buf.length)
        lib.free(bufPtr)
        if (err) destroy('noise_stream_handhshake_read', err)
      })
    }
  }

  var onhandshakesplit = function (ptr, macSize) {
    if (ptr === streamPtr) {
      decrypt._splitHandshake(ptr)
      encrypt._splitHandshake(ptr, macSize)
    }
  }

  var cleanup = function () {
    if (!ended) {
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
    var err = new Error(s + ' ' + code)
    encrypt.destroy(err)
    decrypt.destroy(err)
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

// var { decrypt: localDecrypt, encrypt: localEncrypt } = module.exports({ initiator: true })
// var { decrypt: remoteDecrypt, encrypt: remoteEncrypt } = module.exports()

// localEncrypt.pipe(remoteDecrypt).on('data', data => console.log('remote ->', data.toString())).on('end', () => console.log('remote end'))
// remoteEncrypt.pipe(localDecrypt).on('data', data => console.log('local ->', data.toString()))

// localEncrypt.write('hello from local')
// remoteEncrypt.write('hello from remote')

// setTimeout(function () {
//   localEncrypt.write('hello 2')
//   localEncrypt.end()
//   remoteEncrypt.end()
// }, 500)