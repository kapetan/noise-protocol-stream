# noise-protocol-stream

Node stream wrapper for [Noise Protocol](http://noiseprotocol.org) [C implementation](https://github.com/rweather/noise-c) compiled to WebAssembly.

    npm install noise-protocol-stream

## Usage

The constructor returns a stream pair for encrypting outgoing and decrypting incoming data. Both streams need to be connected for the handshake to succeed.

```javascript
var noise = require('noise-protocol-stream')
var client = noise({ initiator: true })
var server = noise()

client.encrypt.pipe(server.decrypt)
server.encrypt.pipe(client.decrypt)

server.decrypt.on('data', function (data) {
  console.log(data)
})

client.encrypt.write('hello')
```

Client example with TCP socket.

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
