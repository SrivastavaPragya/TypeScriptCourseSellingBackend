
import mongoose from "mongoose"
mongoose.connect("mongodb://127.0.0.1:27017/courseSellingBackendTs").then(()=>{
    console.log("connection is succesful")
 }).catch((e)=>{
console.log(e)
 })


