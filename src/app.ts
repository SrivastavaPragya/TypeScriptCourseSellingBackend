import express from "express"
import './db/conn'
import jwt from 'jsonwebtoken';
import { Admin, User, Course } from './db/models/Schema';
//acquriring route
import route from './routers/routes';

const app=express()


const PORT=process.env.PORT||8000

app.use(express.json());
app.use(route)


app.listen(PORT, () => console.log('Server running on port 8000'));

