require('dotenv').config();

const twilio = require('twilio');
const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

module.exports = async (phone, otp) => {

  console.log('Phone:', phone);
  console.log('OTP:', otp);

 try {
   await client.messages.create({
     body: `Your OTP is ${otp}. It will expire in 5 minutes.`,
     from: process.env.TWILIO_PHONE_NUMBER,
     to: phone,
   });
   console.log('OTP sent successfully');
  } catch (error) {
    console.error('Error sending OTP:', error);
    throw new Error('Failed to send sms: ' + error.message);
  
 }
};
