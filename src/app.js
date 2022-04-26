const cookieParser = require('cookie-parser')
const express = require('express')
const userRoute = require('./routes/user')
const bookRoute = require('./routes/book')
const bookTransactionRoute = require('./routes/book-transaction')
const authRoute = require('./routes/auth')
const cors = require('cors')
const authMiddleware = require('./middleware/auth')

const app = express()

app.use(express.json())
app.use(cookieParser())
app.use(
  cors({
    credentials: true,
    origin: ['http://localhost:8080'],
  })
)
app.use(authMiddleware)

app.use('/user', userRoute)
app.use('/auth', authRoute)
app.use('/book', bookRoute)
app.use('/book-transaction', bookTransactionRoute)

app.use(express.static(__dirname + '/www'))

app.get('/', (req, res) => {
  res.send('Hello World')
})

module.exports = app
