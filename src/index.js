const app = require('./app')
const http = require('http')
const logger = require('node-color-log')
const mongoose = require('mongoose')
const dotenv = require('dotenv')

dotenv.config()

async function main() {
  const port = process.env.PORT ?? 4000
  await mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
      logger.color('green').log('[MongoDB] connected')
    })
    .catch((e) => {
      logger.color('red').error('[MongoDB] connection error')
      logger.color('red').error(e)
      process.exit(1)
    })

  const server = http.createServer(app)
  server.listen(port, () => {
    logger.color('green').log(`[Server] Server is running on port ${port}`)
  })
}

main()
