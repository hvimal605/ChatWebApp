const express = require('express')

const user = require('./routes/user')
const message =require('./routes/message')
const {app , server} = require('./socketIO/server')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const fileUpload = require('express-fileupload')
const path = require('path')

const { cloudinaryConnect } = require('./config/clodinary')

app.use(express.json())
app.use(cookieParser())

app.use(
  fileUpload({
      useTempFiles:true,
      tempFileDir:'/tmp',
  })
)

cloudinaryConnect()
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));  

app.use(cors({
  origin: "http://localhost:5173",
  credentials: true
}));
require("dotenv").config()
const port = process.env.PORT||4000



const db = require('./config/database')

db.dbConnect()


app.use("/api/user",user)
app.use("/api/message",message)


// -------code for deployment-------

if(process.env.NODE_ENV==='production'){
  const dirpath = path.resolve()

  app.use(express.static("./frontend/dist"))
  app.get("*",(req,res)=>{
    res.sendFile(path.resolve(dirpath,"./frontend/dist","index.html"))
  })
}

server.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})