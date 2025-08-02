import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
    host:"HostName",
    port:111,
    auth:{
        user:process.env.SMTP_USER,
        pass:process.env.SMTP_PASS
    }
});
export default transporter;