import express from 'express'
import mysql from 'mysql'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

const app = express();

app.use(express.json())
app.use(cors());

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
//Mở sever express ở port 8081
app.listen(8081, () => {
  console.log('Listening me server, please wake up, give me hope');
})