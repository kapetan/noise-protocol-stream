var stream = require('stream')
var test = require('tape')
var noise = require('../')

var TEST_PRIVATE_KEY = Buffer.from('90000e3a66c18b14888be31ab38573551466193e4805540e65f3916356185866', 'hex')
var TEST_PUBLIC_KEY = Buffer.from('36d359107204cd30cd83291ed295959866c48a6e3e5af9fe720b00af9b624c78', 'hex')

var verifyPromise = function (accept) {
  var fn = null
  var promise = new Promise(function (resolve) {
    fn = resolve
  })

  promise.verify = function (lprk, lpuk, rpuk, cb) {
    fn([lprk, lpuk, rpuk])
    cb(null, accept)
  }

  return promise
}

var createClient = function (options) {
  if (!options) options = {}

  options.initiator = true
  var { decrypt, encrypt } = noise(options)
  return { clientDecrypt: decrypt, clientEncrypt: encrypt }
}

var createServer = function (options) {
  if (!options) options = {}

  var { decrypt, encrypt } = noise(options)
  return { serverDecrypt: decrypt, serverEncrypt: encrypt }
}

var buffer = function (done) {
  var buffer = []

  return new stream.Transform({
    transform: function (data, enc, cb) {
      buffer.push(data)
      cb(null, data)
    },
    flush: function (cb) {
      done(Buffer.concat(buffer))
      cb()
    }
  })
}

test('simple protocol', function (t) {
  t.plan(12)

  var onclientkeys = verifyPromise(true)
  var onserverkeys = verifyPromise(true)
  var { clientDecrypt, clientEncrypt } = createClient({ verify: onclientkeys.verify })
  var { serverDecrypt, serverEncrypt } = createServer({ verify: onserverkeys.verify })

  clientEncrypt
    .pipe(buffer(function (buffer) {
      t.notOk(buffer.includes('test-client-message'), 'should not contain plain text message')
    }))
    .pipe(serverDecrypt)

  serverEncrypt
    .pipe(buffer(function (buffer) {
      t.notOk(buffer.includes('test-server-message'), 'should not contain plain text message')
    }))
    .pipe(clientDecrypt)

  Promise.all([onclientkeys, onserverkeys]).then(function (values) {
    var [, clientLocalPublicKey, clientRemotePublicKey] = values[0]
    var [, serverLocalPublicKey, serverRemotePublicKey] = values[1]

    t.deepEquals(clientLocalPublicKey, serverRemotePublicKey, 'should be equal client keys')
    t.deepEquals(serverLocalPublicKey, clientRemotePublicKey, 'should be equal server keys')
  })

  clientEncrypt.on('handshake', function (lprk, lpuk, rpuk, cb) {
    onclientkeys.then(function (keys) {
      var [clientLocalPrivateKey, clientLocalPublicKey, clientRemotePublicKey] = keys

      t.deepEquals(clientLocalPrivateKey, lprk)
      t.deepEquals(clientLocalPublicKey, lpuk)
      t.deepEquals(clientRemotePublicKey, rpuk)
    })
  })

  clientDecrypt.on('handshake', function (lprk, lpuk, rpuk, cb) {
    onclientkeys.then(function (keys) {
      var [clientLocalPrivateKey, clientLocalPublicKey, clientRemotePublicKey] = keys

      t.deepEquals(clientLocalPrivateKey, lprk)
      t.deepEquals(clientLocalPublicKey, lpuk)
      t.deepEquals(clientRemotePublicKey, rpuk)
    })
  })

  serverDecrypt.on('data', function (data) {
    t.equals(data.toString(), 'test-client-message')
  })

  clientDecrypt.on('data', function (data) {
    t.equals(data.toString(), 'test-server-message')
  })

  clientEncrypt.write('test-client-message')
  serverEncrypt.write('test-server-message')

  clientEncrypt.end()
  serverEncrypt.end()
})

test('protocol with prologue', function (t) {
  t.plan(1)

  var { clientDecrypt, clientEncrypt } = createClient({ prologue: 'test-prologue' })
  var { serverDecrypt, serverEncrypt } = createServer({ prologue: 'test-prologue' })

  clientEncrypt.pipe(serverDecrypt)
  serverEncrypt.pipe(clientDecrypt)

  serverDecrypt.on('data', function (data) {
    t.equals(data.toString(), 'test-client-message')
  })

  clientEncrypt.write('test-client-message')

  clientEncrypt.end()
  serverEncrypt.end()
})

test('protocol with different prologue', function (t) {
  t.plan(2)

  var { clientDecrypt, clientEncrypt } = createClient({ prologue: 'test-prologue-1' })
  var { serverDecrypt, serverEncrypt } = createServer({ prologue: 'test-prologue-2' })

  clientEncrypt.pipe(serverDecrypt)
  serverEncrypt.pipe(clientDecrypt)

  var onerror = function (err) {
    t.equals(err.message, 'noise_stream_handhshake_read 17668')
  }

  clientEncrypt.on('error', onerror)
  clientDecrypt.on('error', onerror)

  clientEncrypt.end()
  serverEncrypt.end()
})

test('protocol with private key', function (t) {
  t.plan(5)

  var onclientkeys = verifyPromise(true)
  var onserverkeys = verifyPromise(true)
  var { clientDecrypt, clientEncrypt } = createClient({ verify: onclientkeys.verify, privateKey: TEST_PRIVATE_KEY })
  var { serverDecrypt, serverEncrypt } = createServer({ verify: onserverkeys.verify })

  clientEncrypt.pipe(serverDecrypt)
  serverEncrypt.pipe(clientDecrypt)

  Promise.all([onclientkeys, onserverkeys]).then(function (values) {
    var [clientLocalPrivateKey, clientLocalPublicKey, clientRemotePublicKey] = values[0]
    var [, serverLocalPublicKey, serverRemotePublicKey] = values[1]

    t.deepEquals(TEST_PRIVATE_KEY, clientLocalPrivateKey)
    t.deepEquals(TEST_PUBLIC_KEY, clientLocalPublicKey)
    t.deepEquals(clientLocalPublicKey, serverRemotePublicKey)
    t.deepEquals(serverLocalPublicKey, clientRemotePublicKey)
  })

  serverDecrypt.on('data', function (data) {
    t.equals(data.toString(), 'test-client-message')
  })

  clientEncrypt.write('test-client-message')

  clientEncrypt.end()
  serverEncrypt.end()
})

test('protocol with verify reject', function (t) {
  t.plan(1)

  var { clientDecrypt, clientEncrypt } = createClient({
    verify: function (lprk, lpuk, rpuk, cb) {
      t.pass('should call verify')
      cb(null, false)
    }
  })

  var { serverDecrypt, serverEncrypt } = createServer()

  clientEncrypt.pipe(serverDecrypt)
  serverEncrypt.pipe(clientDecrypt)

  serverDecrypt.on('data', function (data) {
    t.fail('should not receive data')
  })

  clientEncrypt.write('test-client-message')

  clientEncrypt.end()
  serverEncrypt.end()
})

test('protocol with verify error', function (t) {
  t.plan(3)

  var { clientDecrypt, clientEncrypt } = createClient({
    verify: function (lprk, lpuk, rpuk, cb) {
      t.pass('should call verify')
      cb(new Error('test-error'))
    }
  })

  var { serverDecrypt, serverEncrypt } = createServer()

  var onerror = function (err) {
    t.equals(err.message, 'test-error')
  }

  clientEncrypt.pipe(serverDecrypt)
  serverEncrypt.pipe(clientDecrypt)

  serverDecrypt.on('data', function (data) {
    t.fail('should not receive data')
  })

  clientEncrypt.on('error', onerror)
  clientDecrypt.on('error', onerror)

  clientEncrypt.write('test-client-message')

  clientEncrypt.end()
  serverEncrypt.end()
})

test('buffered decrypt', function (t) {
  t.plan(1)

  var { clientDecrypt, clientEncrypt } = createClient()
  var { serverDecrypt, serverEncrypt } = createServer({
    verify: function (lprk, lpuk, rpuk, cb) {
      setTimeout(function () {
        cb(null, true)
      }, 0)
    }
  })

  clientEncrypt.pipe(serverDecrypt)
  serverEncrypt.pipe(clientDecrypt)

  serverDecrypt.on('data', function (data) {
    t.equals(data.toString(), 'test-client-message')
  })

  clientEncrypt.write('test-client-message')

  clientEncrypt.end()
  serverEncrypt.end()
})

test('big data', function (t) {
  t.plan(1)

  var { clientDecrypt, clientEncrypt } = createClient()
  var { serverDecrypt, serverEncrypt } = createServer()
  var message = Buffer.alloc(65535).fill('test-data')

  clientEncrypt.pipe(serverDecrypt)
  serverEncrypt.pipe(clientDecrypt)

  serverDecrypt.on('data', function (data) {
    t.deepEquals(data, message)
  })

  clientEncrypt.write(message)

  clientEncrypt.end()
  serverEncrypt.end()
})
