var test = require('tape')
var noise = require('../')

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
  var { clientDecrypt, clientEncrypt } = createClient()
  var { serverDecrypt, serverEncrypt } = createServer()

  clientEncrypt.pipe(serverDecrypt)
  serverEncrypt.pipe(clientDecrypt)

  serverDecrypt.on('data', function (data) {
    t.equals(data.toString(), 'test-client-message')
  })

  clientDecrypt.on('data', function (data) {
    t.equals(data.toString(), 'test-server-message')
  })

  clientEncrypt.write('test-client-message')
  serverEncrypt.write('test-server-message')

  t.plan(2)
})
