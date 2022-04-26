const dayjs = require('dayjs')

const BORROW_FINE_RATE = {
  นักเรียน: {
    หนังสือ: 1,
    ซีดี: 1,
    หนังสือจอง: 5,
  },
  ครู: {
    หนังสือ: 1,
    ซีดี: 1,
    หนังสือจอง: 5,
  },
  เจ้าหน้าที่: {
    หนังสือ: 1,
    ซีดี: 1,
    หนังสือจอง: 5,
  },
  บุคคลภายนอก: {
    หนังสือ: 3,
    ซีดี: 3,
    หนังสือจอง: 5,
  },
}

/**
 *
 * @param {*} borrowTranscation require populated book populated user
 * @returns
 */
module.exports.getFineRate = function (borrowTranscation) {
  const { book, user } = borrowTranscation
  const { job } = user
  const { book_type } = book
  const fineRate = BORROW_FINE_RATE[job][book_type]

  const overdued = dayjs(new Date()).diff(borrowTranscation.end_date, 'day') > 0
  return overdued ? fineRate : 0
}

module.exports.BORROW_FINE_RATE = BORROW_FINE_RATE
