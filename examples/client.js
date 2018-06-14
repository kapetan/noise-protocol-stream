var net = require('net')
var noise = require('../')

var socket = net.createConnection(8080)
var client = noise({ initiator: true })

client.encrypt
  .pipe(socket)
  .pipe(client.decrypt)
  .on('data', function (data) {
    console.log(data.toString())
  })

client.encrypt.write('hello')
