import express, { json, response } from 'express'
import mysql from 'mysql'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'
import axios from 'axios'
import CryptoJS from 'crypto-js'
import moment from 'moment'
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import path from 'path';
import multer from 'multer';
import nodemailer from 'nodemailer'

dotenv.config()

const salt = 10

const app = express()

app.use(express.json())
app.use(cors())
app.use(cookieParser())
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use('/audio', express.static(path.join(__dirname, 'audio')));
app.use('/toeic_question_pics', express.static(path.join(__dirname, 'toeic_question_pics')));

//Kết nối tới database crud trên MySQL mở bằng Xampp
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'final_wineng_db'
})

// middleware
function authenToken(req, res, next) {
  const authorizationHeader = req.headers['authorization'] // <string>: `Bearer {token}`
  if (!authorizationHeader) return res.status(401).json({ error: 'Authorization header is missing' });
  const token = authorizationHeader.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Token is missing' }); // Unauthorized error
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, data) => {
    console.log(err, data)
    if (err) return res.sendStatus(403) // Forbidden error
    console.log('authorization successfully !')
    next() // complete verify token 
  })
}

app.post('/refreshToken', (req, res) => { 
  const { refreshToken } = req.body;
  // const refreshToken = req.cookies.refreshToken
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token is missing' });
  // Kiểm tra refresh token trong database
  // const sql = 'SELECT * FROM user WHERE refreshtoken = ?';
  // db.query(sql, [refreshToken], (err, data) => {
  // if (err) return res.status(500).json({ error: 'Server error' });
  // if (data.length === 0) return res.status(403).json({ error: 'Invalid refresh token' });
  // Xác thực refresh token
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, data) => {
    if (err) return res.status(403).json({ error: 'Invalid refresh token' });
    // Tạo access token mới
    const accessToken = jwt.sign(
      {
        username: data.username,
        userid: data.userid,
        ispremium: data.ispremium,
        isadmin: data.isadmin,
        useravatarurl: data.useravatarurl
      }, 
      process.env.ACCESS_TOKEN_SECRET,
      { 
        expiresIn: '15m'
      }
    );
    return res.json({ accessToken });
  });
  // });
})

//Lấy user với id
app.get('/get-user-by-id', (req, res) => {
  const { userid } = req.query;
  const sql = "SELECT * FROM user WHERE userid = ?";
  db.query(sql, [userid], (err, result) => {
    if (err) return res.json({ Message: 'Error for getting user by id' });
    else return res.json(result);
  })
})

//Lấy toàn bộ câu hỏi với examid
app.get('/get-qbank-by-id', (req, res) => {
  const { examid } = req.query;
  const sql = "SELECT * FROM question_bank WHERE examid = ?";
  db.query(sql, [examid], (err, result) => {
    if (err) return res.json({ Message: 'Error for getting question bank info' });
    else return res.json(result);
  })
})

//Lấy tất cả các exam
app.get('/get-exam', (req, res) => {
  const sql = "SELECT * FROM exam";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: 'Error for getting exam info' });
    else return res.json(result);
  })
})
//Lấy tất cả các user
app.get('/get-all-user', (req, res) => {
  const sql = "SELECT * FROM user";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: 'Error for getting exam info' });
    else return res.json(result);
  })
})
//Lấy user theo email
app.get('/get-user-by-email', (req, res) => {
  const {email} = req.query
  const sql = "SELECT * FROM user where useremail = ?";
  db.query(sql, [email], (err, result) => {
    if (err) return res.json({ Message: 'Error for getting exam info' });
    else return res.json(result);
  })
})
//Cập nhật giá trị mới cho user
app.put('/update-user-info', (req, res) => {
  const { userid, username, userfullname, userphone, useravatarurl } = req.body;
  const sql = `
    UPDATE user
    SET
      username = ?,
      userfullname = ?,
      userphone = ?,
      useravatarurl = ?
    WHERE userid =?
  `;
  db.query(sql, [username, userfullname, userphone, useravatarurl, userid], (err, result) => {
    if (err) {
      console.error('Error updating user info:', err);
      return res.status(500).json({ error: 'Server error while updating user info' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({ message: 'User updated successfully' });
  })
})

// Xóa user
app.post('/delete-user-by-id', (req, res) => {
  console.log('call me delete user')
  const {userid} = req.body
  const sql = `
    delete from user
    where userid = ?
  `
  db.query(sql, [userid], (err, result) => {
    if(err) return req.json({Status: 'Error'})
    return res.json({Status: 'Success'})
  })
})

//Lưu kết quả bài thi
app.post('/store-exam-result', (req, res) => {
  console.log('Received data:', req.body); // Log the received data

  const new_participants = req.body.examtotalparticipants + 1

  const sql_update_totalparticipants = `
    update exam 
    set examtotalparticipants = ?
    where examid = ?`

  db.query(sql_update_totalparticipants, [new_participants, req.body.examid], (err, result) => {
    if(err) return res.json({Error: 'Error when update examtotalparticipants: ' + err})
  })

  const sql = `
    INSERT INTO examresult
    (examname,numscorrect, numswrong, numsskip, duration, accuracy, totalscore, listeningscore, numslisteningcorrect, readingscore, numsreadingcorrect, examid, userid, datetakeexam)
    VALUES (?)
  `;
  const values = [
    req.body.examname,
    req.body.numscorrect,
    req.body.numswrong,
    req.body.numsskip,
    req.body.duration,
    req.body.accuracy,
    req.body.totalscore,
    req.body.listeningscore,
    req.body.numslisteningcorrect,
    req.body.readingscore,
    req.body.numsreadingcorrect,
    req.body.examid,
    req.body.userid,
    req.body.datetakeexam,
  ];

  db.query(sql, [values], (err, result) => {
    if (err) {
      console.error('Error inserting data:', err);
      return res.json({ Error: 'Inserting data Error in server' });
    }
    return res.json({ Status: 'Success' });
  });
});
//Lấy tất cả exam result
app.get('/get-all-exam-result', (req, res) => {
  const sql = "SELECT * FROM examresult";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: 'Error for getting all exam info' });
    else return res.json(result);
  })
})

app.get('/count-exam-result', (req, res) => {
  const sql = "SELECT count(*) as numberofexamresult FROM examresult";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: 'Error for count exam result' });
    else return res.json(result);
  })
})

//Lấy danh sách kết quả đề thi với userid
app.get('/get-exam-result-by-id', (req,res) => {
  const sql = "SELECT * FROM examresult WHERE userid = ?";
  const {userid} = req.query;
  db.query(sql, [userid], (err, result) => {
    if (err) return res.json({ Message: 'Error for getting exam result' });
    else return res.json(result);
  })
});
//Lấy danh sách kết quả đề thi với date
app.get('/get-exam-result-with-date', (req,res) => {
  const sql = `
    select datetakeexam, count(*) as takeexamtimes
    from examresult
    group by datetakeexam
    order by datetakeexam desc
    limit 5
  `
  db.query(sql, (err, result) => {
    if(err) return res.json({Error: 'Error when get examresult with date'})
    return res.json(result)
  })
})

app.get('/get-total-listening-reading-total-score', (req, res) => {
  const sql = `
    select sum(listeningscore) as listeningscore, sum(readingscore) as readingscore, sum(totalscore) as totalscore
    from examresult
  `
  db.query(sql, (err, result) => {
    if(err) return res.json({Error: "Error when get listening score"})
    return res.json(result)
  })
})

//Đăng ký tài khoản mới
app.post('/register', (req, res) => {
  console.log('call me register')
  const sql_check_if_exist = 'select * from user where useremail = ? or userphone = ?'
  db.query(sql_check_if_exist, [req.body.email, req.body.phonenumber], (err, checkResult) => {
    if(err) return res.json({Status: 'Error', Error: err})
    if(checkResult.length > 0) {
      return res.json({Status: 'Error', Error: 'Email hoặc số điện thoại đã tồn tại'})
    }
    else {
      const sql = 'insert into user(username, userphone, userpass, useremail) values (?)'
      bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
        if (err) return res.json({Status: 'Error', Error: 'error for hashing password' })
        const values = [
          req.body.username,
          req.body.phonenumber,
          hash,
          req.body.email
        ]
        db.query(sql, [values], (err, result) => {
          if (err) return res.json({ Status: 'Error', Error: 'Inseting data Error in server' })
          return res.json({ Status: 'Success' })
        })
      })
    }
  })
  
})

app.post('/login', (req, res) => {
  const sql = 'select * from user where useremail = ?'
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Status: 'Error', Error: err })
    if (data.length > 0) {
      bcrypt.compare(req.body.password.toString(), data[0].userpass, (err, response) => {
        if (err) return res.json({ Status: 'Error', Error: 'Password compare error' })
        if (response) {
          const userid = data[0].userid;
          const name = data[0].username
          const ispremium = data[0].ispremium
          const isadmin = data[0].isadmin
          const useravatarurl = data[0].useravatarurl
          const accessToken = jwt.sign({ name, userid, ispremium, isadmin, useravatarurl }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '60m' })
          const refreshToken = jwt.sign({ name, userid, ispremium, isadmin, useravatarurl }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' })
          res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: false, // set to true when deploy to production
            path: '/',
            sameSite: 'strict'
          })
          // // Lưu refresh token vào database
          // const updateTokenSql = 'UPDATE user SET refreshtoken = ? WHERE useremail = ?';
          // db.query(updateTokenSql, [refreshToken, req.body.email], (err) => {
          //   if (err) return res.json({ Error: 'Error updating refresh token' });
          //   return res.json({ Status: 'Success', accessToken, refreshToken });
          // });
          return res.json({ Status: 'Success', accessToken, refreshToken })
        }
        else {
          return res.json({ Status: 'Error', Error: 'Mật khẩu không đúng' })
        }
      })
    } else {
      return res.json({ Status: 'Error', Error: 'Không tồn tại người dùng với email này !' })
    }
  })
})
app.post('/send-recovery-email', async (req, res) => {
  console.log('call me send-recovery-email')
  const { OTP, recipient_email } = req.body
  console.log('check opt and recipient-email: ', OTP, recipient_email)
  if (!recipient_email) {
    return res.status(400).json({ message: 'Email address is required!' });
  }
  //Cấu hình transporter (sử dụng gmail)
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // true for port 465, false for other ports
    auth: {
      user: process.env.MAIL_USERNAME,
      pass: process.env.MAIL_PASSWORD,
    },
  });
  try {
    const info = await transporter.sendMail({
      from: '"Maddison Foo Koch 👻" <huynhanh.170504@gmail.com>', // sender address
      to: recipient_email, // list of receivers
      subject: "Hello ✔", // Subject line
      text: "YOUR OTP CODE: " + OTP, // plain text body
      html: "<b>YOUR OTP CODE: " + OTP + "</b>", // html body
    });
    console.log('Email sent: ' + info);
  }
  catch (err) {
    return res.json({Error: err})
  }
  return res.json({Status: 'Success'})
})

app.post('/update-password-by-email', (req, res) => {
  console.log('call me update password-by-email')
  const {resetEmail, password} = req.body
  console.log('check resetEmail and password: ', resetEmail, password) //check resetEmail and password:  huynhanh.170504@gmail.com 321
  const sql = `
    update user
    set userpass = ? 
    where useremail = ?
  `
  bcrypt.hash(password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Error: 'error for hashing password in update statement' })
    db.query(sql, [hash, resetEmail], (err, result) => {
      if (err) return res.json({ Status: 'Error', Message: err })
      return res.json({ Status: 'Success' })
    })
  })
})

app.post('/logout', authenToken, (req, res) => {
  res.clearCookie("accessToken")
  res.clearCookie("refreshToken")
  return res.sendStatus(200).json({ Message: "Logged out !" })
})

// it's payment time !
const config = {
  app_id: "2553",
  key1: "PcY4iZIKFCIdgZvA6ueMcMHHUbRLYjPL",
  key2: "kLtgPl8HHhfvMuDHPwKfgfsY4Ydm9eIz",
  endpoint: "https://sb-openapi.zalopay.vn/v2/create"
};

app.post('/payment', async (req, res) => {
  const embed_data = {
    redirecturl: 'http://localhost:3000/'
  };

  const items = [{"itemid":"pre","itemname":"premium","itemprice":1000000}];
  const transID = Math.floor(Math.random() * 1000000);
  const order = {
    app_id: config.app_id,
    app_trans_id: `${moment().format('YYMMDD')}_${transID}`, // translation missing: vi.docs.shared.sample_code.comments.app_trans_id
    app_user: "user123", // req.body.userid
    app_time: Date.now(), // miliseconds
    item: JSON.stringify(items),
    embed_data: JSON.stringify(embed_data),
    amount: 1000000,
    description: `Payment for the order #${transID}`,
    bank_code: "",
    title: "Thanh toán cho Premium"
    // phone: req.body.phonenumber,
    // email: req.body.email
  }; 

  // appid|app_trans_id|appuser|amount|apptime|embeddata|item
  const data = config.app_id + "|" + order.app_trans_id + "|" + order.app_user + "|" + order.amount + "|" + order.app_time + "|" + order.embed_data + "|" + order.item;
  order.mac = CryptoJS.HmacSHA256(data, config.key1).toString();

  try {
    const result = await axios.post(config.endpoint, null, { params: order })
    console.log('check result data after pay: ', result.data)
    if(result.data.return_code === 1) {
      return res.json({order_url: result.data.order_url, return_code: result.data.return_code})
    }
  }
  catch (err) { 
    console.log("error when payment: ", err.message);
  }
})
app.post('/set-premium', authenToken, (req, res) => {
  // console.log('call me set-premium')
  const {userid, timepremium, payid} = req.body;
  console.log('check userid-timepremium-payid: ', userid, '-', timepremium, '-', payid)
  const sql_save_premium_info = `insert into premium(userid, timepremium, payid) values (?)`
  const premium_info = [
    userid, 
    timepremium, 
    payid
  ]
  db.query(sql_save_premium_info, [premium_info], (err, save_result) => {
    if(err) {
      console.log('Error while save premium info: ', err)
      return res.json({Status: 'Error', Error: err})
    }
  })
  if(userid) {
    const sql = `
      UPDATE user  
      SET ispremium = 1 
      WHERE userid = ? 
    `
    db.query(sql, [userid], (err, result) => {
      if(err) return res.json({Error: 'Error when trying to set premium for user with id = ' + userid})
      return res.json({Status: 'Success'})
    }) 
  }
  else {
    return res.json({Status: 'Failed'})
  }
})
app.post('/add-comment', (req, res) => {
  // console.log('call me add comment')
  const {userid, examid, comment, rate, commentdate} = req.body
  const sql = 'INSERT INTO comment(userid, examid, commenttext, rate,    commentdate ) VALUES (?)'
  const values = [
    userid, 
    examid, 
    comment, 
    rate, 
    commentdate
  ]
  db.query(sql, [values], (err, results) => {
    if(err) return res.json({Error: 'Error when insert comment'})
    return res.json({Status: 'Success'})
  })
})
app.get('/get-comment-by-id', (req, res) => {
  // console.log('call me get comment')
  const {examid} = req.query
  // console.log('check examid: ', examid)
  const sql = `
    select commenttext, commentdate, examid, rate, user.username
    from comment 
    left outer join user on comment.userid = user.userid 
    where examid = ? 
    order by rate desc
    limit 3
    `
  db.query(sql, [examid], (err, results) => {
    if(err) return res.json({Error: `Error when get comment: ${err}`})
    // console.log('check comments after get: ', results)
    return res.json(results)
  })
})

//DÙNG MULTER CHO AVATAR USER
//Tạo nơi chứa ảnh (uploads)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueName = `${Date.now()}-${file.originalname}`; // Đặt tên tệp duy nhất
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage: storage
});


app.post('/upload-avatar', upload.single('avatar'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded!');
  }
  const fileUrl = `http://localhost:8081/uploads/${req.file.filename}`;
  res.status(200).json({ avatarUrl: fileUrl });
});


app.use('/uploads', express.static('uploads'));



app.get('/count-comment-by-id', (req, res) => {
  // console.log('call me count total comment')
  const {examid} = req.query
  const sql = `
    select count(*) as totalcomments
    from comment
    where examid = ?
  `
  db.query(sql, [examid], (err, results) => {
    if(err) return res.json({Error: 'Error when count comment: ' + err})
    return res.json(results)
  })
})

//Mở sever express ở port 8081
app.listen(8081, () => {
  console.log(`Listening me server, please wake up, give me hope http://localhost:8081/`);
})