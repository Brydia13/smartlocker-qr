const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'cricrilope3@gmail.com',
    pass: 'rqnr gdnv dfnp upmj'
  }
});

async function sendEmail(to, subject, html, attachmentUrl = null) {
  const mailOptions = {
    from: '"SmartLock System" cricrilope3@gmail.com>',
    to,
    subject,
    html
  };

  if (attachmentUrl) {
    mailOptions.attachments = [
      {
        filename: 'qr-code.png',
        path: attachmentUrl
      }
    ];
  }

  return transporter.sendMail(mailOptions);
}

module.exports = { sendEmail };
