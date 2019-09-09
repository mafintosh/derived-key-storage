const RAS = require('random-access-storage')
const thunky = require('thunky')
const varint = require('varint')

module.exports = keyPair

function keyPair (storage, derive) {
  const load = thunky(function (cb) {
    storage.stat(function (err, st) {
      if (err) return createNew()
      storage.read(0, st.size, function (err, buf) {
        if (err || buf.length < 2) return createNew()

        let len = 0
        try {
          len = varint.decode(buf, 0)
        } catch (err) {
          return createNew()
        }

        const offset = varint.decode.bytes
        if (offset + len !== buf.length) return createNew()
        const name = buf.slice(offset)
        derive(name, cb)
      })
    })

    function createNew () {
      derive(null, function (err, res) {
        if (err) return cb(err)
        const name = res.name
        const buf = Buffer.allocUnsafe(varint.encodingLength(name.length) + name.length)
        varint.encode(name.length, buf, 0)
        name.copy(buf, varint.encode.bytes)
        storage.write(0, buf, function (err) {
          if (err) return cb(err)
          cb(null, res)
        })
      })
    }
  })

  const key = new RAS({
    stat (req) {
      req.callback(null, { size: 32 })
    },
    read (req) {
      load(function (err, res) {
        if (err) return req.callback(err)
        req.callback(null, res.publicKey)
      })
    },
    close (req) {
      storage.close(function (err) {
        req.callback(err)
      })
    }
  })

  const secretKey = new RAS({
    stat (req) {
      req.callback(null, { size: 64 })
    },
    read (req) {
      load(function (err, res) {
        if (err) return req.callback(err)
        req.callback(null, res.secretKey)
      })
    },
    close (req) {
      storage.close(function (err) {
        req.callback(err)
      })
    }
  })

  return { key, secretKey }
}
