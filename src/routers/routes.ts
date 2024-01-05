import express from "express";
const router= express.Router()
import {Admin,User,Course}  from "../db/models/Schema";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Request,Response,NextFunction } from "express";




const SECRET = 'SECr3mm'; 

interface JWTPayload {
  id: string;
  username: string; 
  
}



const authenticateJwt = (req: Request & { user?: JWTPayload }, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET, (err, payload: any) => {
      if (err) {
        return res.sendStatus(403);
      }
      if (!payload || typeof payload === "string") {
        return res.sendStatus(403);
      }

      // Assuming payload is of type JWTPayload
      req.user = payload as JWTPayload;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};


router.post('/admin/signup', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username });
  if (admin) {
      res.status(403).json({ message: "Admin already exists" });
  } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newAdmin = new Admin({ username, password: hashedPassword });
      await newAdmin.save();
      const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
      res.status(200).json({ message: "Admin created successfully", token });
  }
});

router.post('/admin/login', async (req, res) => {
  // It's more common to send credentials in the request body instead of headers
  const { username, password } = req.body; // Changed from req.headers to req.body

  if (typeof username === 'string' && typeof password === 'string') {
    const admin = await Admin.findOne({ username });

    // Check if admin exists and admin.password is a string
    if (admin && admin.password && await bcrypt.compare(password, admin.password)) {
      const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
      res.status(200).json({ message: "Admin logged in successfully", token });
    } else {
      res.status(403).json({ message: "Invalid username or password" });
    }
  } else {
    res.status(400).json({ message: "Bad request: Username and password must be provided as strings" });
  }
});

  
  router.post('/admin/courses', authenticateJwt,async(req,res)=>{
    const{title,description,price,imageLink,published}=req.body
    const course= await Course.findOne({title})
    if(course){
      res.status(403).json({ message: "Course already exists" });
    }
    else{
      const newCourse=new Course({title,description,price,imageLink,published})
     await newCourse.save();
     res.status(200).json({ message: "Course created successfully", courseId: newCourse._id });// in mongodb course id is automatically generated we jut have to retrieve it
    }


  })
  router.put('/admin/courses/:courseId', authenticateJwt, async (req, res) => {
    const course = await Course.findByIdAndUpdate(req.params.courseId, req.body, { new: true });
    if (course) {
      res.json({ message: 'Course updated successfully',course });
    } else {
      res.status(404).json({ message: 'Course not found' });
    }
  });


  router.delete('/admin/courses/:courseId', authenticateJwt, async (req, res) => {
    try {
        const course = await Course.findByIdAndDelete(req.params.courseId);
        if (!course) {
            return res.status(404).json({ message: 'Course not found' });
        }
        res.json({ message: 'Course deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting course' });
    }
});
  
  router.get('/admin/courses', authenticateJwt, async (req, res) => {
    const courses = await Course.find({published:true});
  res.status(200).json({message:"all the courses",courses})
  });



 

router.post('/users/signup', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user) {
      res.status(403).json({ message: "User already exists" });
  } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({ username, password: hashedPassword });
      await newUser.save();
      const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
      res.status(200).json({ message: "User created successfully", token });
  }
});




router.post('/users/login', async (req, res) => {
  const username = req.headers.username;
  const password = req.headers.password;

  if (typeof username === 'string' && typeof password === 'string') {
    const user = await User.findOne({ username });

    // Check if user exists and user.password is not null or undefined
    if (user && user.password && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
      res.status(200).json({ message: "User logged in successfully", token });
    } else {
      res.status(403).json({ message: "Invalid username or password" });
    }
  } else {
    res.status(400).json({ message: "Bad request: Username and password must be provided as strings" });
  }
});


router.get('/users/courses', authenticateJwt, async (req, res) => {
  const courses = await Course.find({published: true});
  res.status(200).json({message:"all the courses",courses})
});

router.post('/users/courses/:courseId', authenticateJwt, async (req: Request & { user?: JWTPayload }, res: Response) => {
  const course = await Course.findById(req.params.courseId);
  if (course) {
    if (req.user && req.user.username) {
      const user = await User.findOne({ username: req.user.username });
      if (user) {
        user.purchasedCourses.push(course._id);

        await user.save();
        res.json({ message: 'Course purchased successfully' });
      } else {
        res.status(403).json({ message: 'User not found' });
      }
    } else {
      res.status(401).json({ message: 'Unauthorized' });
    }
  } else {
    res.status(404).json({ message: 'Course not found' });
  }
});


router.get('/users/purchasedCourses', authenticateJwt, async (req: Request & { user?: JWTPayload }, res: Response) => {
  if (req.user && req.user.username) {
    const user = await User.findOne({ username: req.user.username }).populate('purchasedCourses');
    if (user) {
      res.json({ purchasedCourses: user.purchasedCourses || [] });
    } else {
      res.status(403).json({ message: 'User not found' });
    }
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});


export default router;
