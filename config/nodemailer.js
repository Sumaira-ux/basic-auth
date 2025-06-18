import nodemailer from "nodemailer"

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "sumairapathan400@gmail.com",
    pass: "exmu ixbr ghsj vbhp",
  },
});
export default transporter 