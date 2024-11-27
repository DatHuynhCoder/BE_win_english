import express, { json, response } from 'express'
import mysql from 'mysql'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'
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
    if(err) res.sendStatus(403) // Forbidden error
    next() // complete verify token 
  })
}

app.post('/refreshToken', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token is missing' });
  // Kiểm tra refresh token trong database
  const sql = 'SELECT * FROM user WHERE refreshtoken = ?';
  db.query(sql, [refreshToken], (err, data) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (data.length === 0) return res.status(403).json({ error: 'Invalid refresh token' });
    // Xác thực refresh token
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, data) => {
      if (err) return res.status(403).json({ error: 'Invalid refresh token' });
      // Tạo access token mới
      const accessToken = jwt.sign({ username: data.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
      return res.json({ accessToken });
    });
  });
})

//Lấy toàn bộ câu hỏi với examid
app.get('/get-qbank-by-id', (req, res) => {
  const {examid} = req.query;
  const sql = "SELECT * FROM question_bank WHERE examid = ?";
  db.query(sql,[examid] ,(err, result) => {
    if(err) return res.json({Message: 'Error for getting question bank info'});
    else return res.json(result);
  })
})

//Lấy tất cả các exam
app.get('/get-exam', authenToken, (req, res) => {
  const sql = "SELECT * FROM exam";
  db.query(sql, (err, result) => {
    if(err)return res.json({Message: 'Error for getting exam info'});
    else return res.json(result);
  })
})

app.post('/register', (req, res) => {
  const sql = 'insert into user(username, userphone, userpass, useremail) values (?)'
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if(err) return res.json({Error: 'error for hashing password'})
    const values = [
      req.body.username,
      req.body.phonenumber,
      hash,
      req.body.email
    ] 
    db.query(sql, [values], (err, result) => {
      if(err) return res.json({Error: 'Inseting data Error in server'})
      return res.json({Status: 'Success'})
    })
  })
})

app.post('/login', (req, res) => {
  const sql = 'select * from user where useremail = ?'
  db.query(sql, [req.body.email], (err, data) => {
    if(err) return res.json({Error: 'Login error in server'})
    if(data.length > 0) {
      bcrypt.compare(req.body.password.toString(), data[0].userpass, (err, response) => {
        if(err) return res.json({Error: 'Password compare error'})
        if(response) {
          const name = data[0].username
          const accessToken = jwt.sign({name}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '60m'})
          const refreshToken = jwt.sign({name}, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '7d'})
          // // Lưu refresh token vào database
          // const updateTokenSql = 'UPDATE user SET refreshtoken = ? WHERE useremail = ?';
          // db.query(updateTokenSql, [refreshToken, req.body.email], (err) => {
          //   if (err) return res.json({ Error: 'Error updating refresh token' });
          //   return res.json({ Status: 'Success', accessToken, refreshToken });
          // });
          return res.json({Status: 'Success', accessToken, refreshToken})
        }
        else {
          return res.json({Error: 'Password not matched'})
        }
      })
    } else {
      return res.json({Error: 'No email existed'})
    }
  })
})
//Mở sever express ở port 8081
app.listen(8081, () => {
  console.log(`Listening me server, please wake up, give me hope in http://localhost:8081/`);
})