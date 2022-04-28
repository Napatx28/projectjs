const jwt = require('jsonwebtoken')
const logger = require('node-color-log')

class AccessToken {
  constructor(privateKey, publicKey) {
    this.privateKey = privateKey
    this.publicKey = publicKey
  }

  verify(token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.publicKey, (err, decoded) => {
        if (err) {
          logger.color('red').error(err.stack)
          reject(err)
        }
        resolve(decoded)
      })
    })
  }

  sign(payload) {
    return new Promise((resolve, reject) => {
      jwt.sign(
        payload,
        this.privateKey,
        {
          algorithm: 'ES256',
          expiresIn: '4h',
          issuer: 'libary.io',
        },
        (err, token) => {
          if (err) {
            reject(err)
            return
          }
          resolve(token)
        }
      )
    })
  }
}

const JWT_PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqLFRYqYTurQy06FhCOzKE9ai7Wb/A/ciCxb/BmqhOXoAoGCCqGSM49
AwEHoUQDQgAEMBgul03EbxpE1giYUH/VJzq0psF/zhxRbnwvlr9DhQInEiA1OQRO
lfRJlKqJh0QLTRjdQDA+nPTOjcsmmqIeFg==
-----END EC PRIVATE KEY-----`

const JWT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMBgul03EbxpE1giYUH/VJzq0psF/
zhxRbnwvlr9DhQInEiA1OQROlfRJlKqJh0QLTRjdQDA+nPTOjcsmmqIeFg==
-----END PUBLIC KEY-----`

const accessToken = new AccessToken(JWT_PRIVATE_KEY, JWT_PUBLIC_KEY)

module.exports = { accessToken }
