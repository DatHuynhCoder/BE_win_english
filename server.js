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

dotenv.config()

const salt = 10

const app = express()

app.use(express.json())
app.use(cors())
app.use(cookieParser())

//Kết nối tới database crud trên MySQL mở bằng Xampp
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'wineng_db'
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
    const accessToken = jwt.sign({ username: data.username, userid: data.userid }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
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
app.get('/get-exam', authenToken, (req, res) => {
  const sql = "SELECT * FROM exam";
  db.query(sql, (err, result) => {
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

//Lưu kết quả bài thi
app.post('/store-exam-result', (req, res) => {
  console.log('Received data:', req.body); // Log the received data

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

//Lấy danh sách kết quả đề thi với userid
app.get('/get-exam-result-by-id', (req,res) => {
  const sql = "SELECT * FROM examresult WHERE userid = ?";
  const {userid} = req.query;
  db.query(sql, [userid], (err, result) => {
    if (err) return res.json({ Message: 'Error for getting exam result' });
    else return res.json(result);
  })
});

//Đăng ký tài khoản mới
app.post('/register', (req, res) => {
  const sql = 'insert into user(username, userphone, userpass, useremail) values (?)'
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Error: 'error for hashing password' })
    const values = [
      req.body.username,
      req.body.phonenumber,
      hash,
      req.body.email
    ]
    db.query(sql, [values], (err, result) => {
      if (err) return res.json({ Error: 'Inseting data Error in server' })
      return res.json({ Status: 'Success' })
    })
  })
})

app.post('/login', (req, res) => {
  const sql = 'select * from user where useremail = ?'
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: 'Login error in server' })
    if (data.length > 0) {
      bcrypt.compare(req.body.password.toString(), data[0].userpass, (err, response) => {
        if (err) return res.json({ Error: 'Password compare error' })
        if (response) {
          const userid = data[0].userid;
          const name = data[0].username
          const accessToken = jwt.sign({ name, userid }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '60m' })
          const refreshToken = jwt.sign({ name, userid }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' })
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
          return res.json({ Error: 'Password not matched' })
        }
      })
    } else {
      return res.json({ Error: 'No email existed' })
    }
  })
})

app.post('/logout', authenToken, (req, res) => {
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
    redirecturl: 'http://localhost:3000/user'
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
      return res.json({order_url: result.data.order_url})
    }
  }
  catch(err) {
    console.log("error when payment: ", err.message);
  }
})

//Mở sever express ở port 8081
app.listen(8081, () => {
  console.log(`Listening me server, please wake up, give me hope in http://localhost:8081/`);
})