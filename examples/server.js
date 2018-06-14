var net = require('net')
var noise = require('../')

net.createServer(function (socket) {
  var server = noise()

  server.encrypt
    .pipe(socket)
    .pipe(server.decrypt)
    .pipe(server.encrypt)
}).listen(8080)
