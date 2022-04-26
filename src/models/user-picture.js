const mongoose = require('mongoose')

const { toString, toBuffer: ogBuffer } = require('uuid-buffer')
const { v4: uuidv4 } = require('uuid')

function toBuffer(uuid) {
  console.log(uuid)
  if (uuid instanceof Buffer) {
    return uuid
  }

  return ogBuffer(uuid)
}

const UserPictureSchema = new mongoose.Schema({
  _id: {
    type: Buffer,
    subtype: 4,
    get: (_) => (_ ? toString(_) : null),
    set: toBuffer,
    alias: 'profilePicture',
    required: false,
    default: uuidv4,
  },
  user: {
    type: String,
    ref: 'users',
    required: false,
    default: null,
  },
  extname: { type: String, required: true },
})

module.exports.userPictureModel = mongoose.model(
  'user_pictures',
  UserPictureSchema
)
