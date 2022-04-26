const mongoose = require('mongoose')

const bookTransactionSchema = new mongoose.Schema({
  book: { ref: 'books', type: mongoose.Schema.Types.ObjectId, required: true },
  user: { ref: 'users', type: String, required: true },
  start_date: { type: Date, required: true, default: new Date() },
  end_date: {
    type: Date,
    required: true,
    alias: 'endDate',
  },
  returned_date: {
    type: Date,
    required: false,
    default: null,
    alias: 'returnedDate',
  },
})

module.exports.bookTransactionModel = mongoose.model(
  'book_transactions',
  bookTransactionSchema
)
