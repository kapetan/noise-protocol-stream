delete global.WebAssembly

var test = require('tape')
var noise = require('../')

test('unsupported', function (t) {
  t.plan(2)

  t.equals(noise.supported, false)
  t.doesNotThrow(function () {
    noise()
  })
})
