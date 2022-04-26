const dayjs = require('dayjs')
const { Router } = require('express')
const { body, query } = require('express-validator')
const { accessToken } = require('../utils/access-token.js')
const hashTool = require('../utils/hash.js')
const { userModel } = require('../models/user.js')
const jwt = require('jsonwebtoken')
const logger = require('node-color-log')

const router = Router()

router.post(
  '/sign-in',
  body('username').isString(),
  body('password').isString(),
  async (req, res) => {
    try {
      const { username, password } = req.body
      const user = await userModel
        .findOne({ username })
        .populate('picture')
        .exec()
      if (!user) {
        res.status(401).json({
          error: 'Invalid username or password',
        })
        return
      }
      const isValid = await hashTool.compare(password, user.password)
      if (!isValid) {
        res.status(401).json({
          error: 'Invalid username or password',
        })
        return
      }

      delete user.password

      const payload = {
        id: user._id,
        username: user.username,
        prefix: user.prefix,
        firstName: user.firstName,
        lastName: user.lastName,
        faculty: user.faculty,
        department: user.department,
        role: user.role,
        job: user.job,
        picture: user.picture?._id,
      }

      const token = await accessToken.sign(payload)

      res
        .cookie('access_token', token, {
          expires: dayjs().add(8, 'hour').toDate(),
        })
        .json({
          accessToken: token,
          ...payload,
        })
    } catch (err) {
      logger.color('red').error(err.stack)
      res.status(500).json({
        error: err.message,
      })
    }
  }
)

router.post('/sign-out', async (req, res) => {
  try {
    res.clearCookie('access_token')
    res.json({
      message: 'Sign out success',
    })
  } catch (err) {
    res.status(500).json({
      error: err.message,
    })
  }
})

router.get('/verify', query('token').isJWT(), async (req, res) => {
  try {
    res.status(200).json(await accessToken.verify(req.query.token))
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError) {
      res.status(401).json({
        error: 'Invalid token',
      })
      return
    }
    res.status(500).json({
      error: err.message,
    })
  }
})

module.exports = router
