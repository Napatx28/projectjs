const bcrypt = require('bcrypt')

module.exports.hash = async (password) => {
  const salt = await bcrypt.genSalt(10)
  return bcrypt.hash(password, salt)
}

module.exports.compare = (password, hashPassword) =>
  bcrypt.compare(password, hashPassword)
