const mongoose = require('mongoose');
const accountSchema = new mongoose.Schema({
    fullName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    phoneNumber: {
      type: String,
      required: true,
    },
    profilePhoto: {
      type: String,
      required: true,
    },
    password: {
        type: String,
        required: true,
    },
    role:{
      type: String,
      required: true,
    }
  });
  const Account = mongoose.model(('Account'), accountSchema);

  module.exports = Account;