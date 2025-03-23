const Otp = require('../models/otp.model');
const generateOtp = require('../utils/otpGenerator');
const sendEmail = require('../utils/sendEmail');
const sendSMS = require('../utils/sendSMS');

// remove it in the end
exports.clearOtpDatabase = async (req, res) => {
  try {
    await Otp.deleteMany({});
    res.status(200).json({ message: 'All OTP records cleared successfully' });
  } catch (err) {
    console.error('Database Clear Error:', err);
    res.status(500).json({ message: 'Error clearing OTP records' });
  }
};

const rateLimit = {
  maxAttempts: 3,
  windowMs: 60 * 60 * 1000, 
  blockDuration: 24 * 60 * 60 * 1000 
};

exports.generateOtp = async (req, res, next) => {
  const { email, phone } = req.body;
  
  if (!email && !phone) {
    return res.status(400).json({ message: 'Email or phone is required.' });
  }

  try {
    // Rate limiting check
    const attempts = await Otp.countDocuments({
      $or: [
        email ? { email } : null, 
        phone ? { phone } : null
      ].filter(Boolean),
      createdAt: { $gte: new Date(Date.now() - rateLimit.windowMs) }
    });

    if (attempts >= rateLimit.maxAttempts) {
      return res.status(429).json({
        message: 'Too many OTP requests. Please try again later.',
        nextAttemptAllowed: new Date(Date.now() + rateLimit.blockDuration)
      });
    }
    
    
    if (email) {
      await Otp.deleteMany({ email });
    }
    if (phone) {
      await Otp.deleteMany({ phone });
    }

    const otp = generateOtp();
    const currentTime = new Date();
    const expirationTime = new Date(currentTime.getTime() + 5 * 60 * 1000);

    
    const otpRecord = new Otp({
      email: email || null,
      phone: phone || null,
      otp: otp,
      expiration: expirationTime,
      attempts: 0,
    });
   
    const savedRecord = await otpRecord.save();
    
    let emailSent = false;
    let smsSent = false;
    let errors = [];
    
    
    if (email) {
      try {
        await sendEmail(email, otp);
        emailSent = true;
      } catch (emailError) {
        errors.push(`Email error: ${emailError.message}`);
        console.error('Email sending failed:', emailError);
      }
    }
    
    
    if (phone) {
      try {
        await sendSMS(phone, otp);
        smsSent = true;
      } catch (smsError) {
        errors.push(`SMS error: ${smsError.message}`);
        console.error('SMS sending failed:', smsError);
      }
    }
    
    
    if ((email && phone && !emailSent && !smsSent) || 
        (email && !phone && !emailSent) || 
        (phone && !email && !smsSent)) {
      await Otp.deleteOne({ _id: otpRecord._id });
      return res.status(500).json({ 
        message: 'Failed to send OTP through any method', 
        errors 
      });
    }
    
  
    res.status(200).json({ 
      message: 'OTP sent successfully',
      email_sent: email ? emailSent : null,
      sms_sent: phone ? smsSent : null,
      errors: errors.length > 0 ? errors : undefined
    });
    
  } catch (err) {
    console.error('OTP Generation Error:', err);
    res.status(500).json({ message: 'Error sending OTP' });
  }
};

exports.verifyOtp = async (req, res) => {
  const { email, phone, otp: enteredOtp } = req.body;

  try {
    const otpRecord = req.otpRecord;
    
    if (!otpRecord)
      return res.status(404).json({ error: 'OTP not found' });

    if (otpRecord.otp !== parseInt(enteredOtp))
      return res.status(400).json({ error: 'Invalid OTP' });

    
    await Otp.deleteOne({ _id: otpRecord._id });

    res.status(200).json({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('OTP Verification Error:', error);
    res.status(500).json({ message: 'Error verifying OTP' });
  }
};