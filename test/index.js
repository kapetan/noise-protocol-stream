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

test('simple protocol', function (t) {
  var onclientkeys = verifyPromise(true)
  var onserverkeys = verifyPromise(true)
  var { clientDecrypt, clientEncrypt } = createClient({ verify: onclientkeys.verify })
  var { serverDecrypt, serverEncrypt } = createServer({ verify: onserverkeys.verify })

  clientEncrypt.pipe(serverDecrypt)
  serverEncrypt.pipe(clientDecrypt)

  Promise.all([onclientkeys, onserverkeys]).then(function (values) {
    var [, clientLocalPublicKey, clientRemotePublicKey] = values[0]
    var [, serverLocalPublicKey, serverRemotePublicKey] = values[1]

    t.deepEquals(clientLocalPublicKey, serverRemotePublicKey, 'should be equal client keys')
    t.deepEquals(serverLocalPublicKey, clientRemotePublicKey, 'should be equal server keys')
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

  t.plan(4)
})

test('protocol with prologue', function (t) {
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

  t.plan(1)
})

test('protocol with different prologue', function (t) {
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

  t.plan(2)
})

test('protocol with private key', function (t) {
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

  t.plan(5)
})

test('protocol with verify reject', function (t) {
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

  t.plan(1)
})

test('protocol with verify error', function (t) {
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

  t.plan(3)
})
