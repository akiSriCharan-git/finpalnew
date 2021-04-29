const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');
var bcrypt = require('bcrypt-nodejs');



const userSchema = new mongoose.Schema({
  name: String,
  birthday: Date,
  address: {
    housenumber: String,
    street: String,
    city: String,
    state: String,
    country: String,
    pincode: Number,
  },
  email: String,
  username: String,
  password: String,
  phone: String,
  otp: Number,
  otpexpire: Date,
  seller:{
    type: Boolean,
    default: false
  }
});

// user.save() hashes the passsword
userSchema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

userSchema.plugin(passportLocalMongoose);

mongoose.model('User', userSchema);
