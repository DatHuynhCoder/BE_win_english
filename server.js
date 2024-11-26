import express, { json, response } from 'express'
import mysql from 'mysql'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import cookieParser from 'cookie-parser'
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

//Xử lý yêu cầu get của React
app.get('/getQbank', (req, res) => {
  const sql = "SELECT * FROM question_bank";
  db.query(sql, (err, result) => {
    if(err) return res.json({Message: 'Error inside server'});
    else res.json(result);
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
          return res.json({Status: 'Success'})
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