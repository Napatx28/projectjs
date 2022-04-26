const logger = require('node-color-log')
const { accessToken } = require('../utils/access-token')

module.exports = async (req, res, next) => {
  const { authorization } = req.headers
  if (!authorization) {
    next()
    return
  }

  const bearerPattern = /Bearer (.+)/
  const token = bearerPattern.exec(authorization)[1]

  if (!token) {
    next()
    return
  }

  try {
    const decoded = await accessToken.verify(token)
    req.user = decoded
    next()
  } catch (e) {
    logger.color('red').error(e.stack)
    next()
    return
  }
}
