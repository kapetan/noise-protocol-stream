# noise-protocol-stream

Node stream wrapper for [Noise Protocol](http://noiseprotocol.org) [C implementation](https://github.com/rweather/noise-c) compiled to WebAssembly.

    npm install noise-protocol-stream

## Usage

The constructor returns a stream pair for encrypting outgoing and decrypting incoming data. Both streams need to be connected for the initial noise handshake to succeed. After the handshake is complete writing to the encrypt stream will output the encrypted the data and reading from the decrypt stream returns the decrypted data (note that it's not possible to connect the same encrypt and decrypt pair directly).

```javascript
var net = require('net')
var noise = require('noise-protocol-stream')

var socket = net.createConnection(8080)
var client = noise({ initiator: true })

client.encrypt.pipe(socket).pipe(client.decrypt)

client.decrypt.on('data', function (data) {
  console.log(data)
})

client.encrypt.write('hello')
```

The `Noise_XX_25519_AESGCM_SHA256` handshake pattern is used to establish a secure connection, it supports mutual authentication and transmission of static public keys. If no key is specified in the constructor a new one will be created.

Constructor options:

```javascript
{
  initiator: true,                       // Protocol initiator or responder.
  prologue: Buffer.from(prologue),       // Data that both parties want to confirm is identical.
  privateKey: Buffer.from(privateKey),   // Static private key. Public key is computed from it.
  verify: function () {}                 // Verify remote public key before any actual communication.
}
```

The `verify` function is called with the local key pair, the received remote public key and a callback function wich must be called to either accept or terminate the connection. If no `verify` function is provided the default is to accept any connection.

```javascript
var net = require('net')
var noise = require('noise-protocol-stream')

var TRUSTED_PUBLIC_KEY = Buffer.from('...')

net.createServer(function (socket) {
  var server = noise({
    verify: function (localPrivateKey, localPublicKey, remotePublicKey, cb) {
      // Calling cb with an error as first argument will also emit an error event on the stream pair.
      // The callback must be called explicitly with true to accept.
      if (TRUSTED_PUBLIC_KEY.equals(remotePublicKey)) cb(null, true)
      else cb(null, false)
    }
  })

  server.encrypt.pipe(socket).pipe(server.decrypt)

  // Emitted after the connection is accepted in the verify function
  server.encrypt.on('handshake', function (localPrivateKey, localPublicKey, remotePublicKey) {
    console.log(remotePublicKey)
  })

  // Reading and writing will only work after the connection is accepted
  server.decrypt.on('data', function (data) {
    console.log(data)
  })

  server.encrypt.write('world')
}).listen(8080)
```

See the [Noise protocol specifications](http://noiseprotocol.org/noise.html) for more details.
