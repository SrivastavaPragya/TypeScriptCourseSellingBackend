"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const router = express_1.default.Router();
const Schema_1 = require("../db/models/Schema");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const SECRET = 'SECr3mm';
const authenticateJwt = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jsonwebtoken_1.default.verify(token, SECRET, (err, payload) => {
            if (err) {
                return res.sendStatus(403);
            }
            if (!payload || typeof payload === "string") {
                return res.sendStatus(403);
            }
            // Assuming payload is of type JWTPayload
            req.user = payload;
            next();
        });
    }
    else {
        res.sendStatus(401);
    }
};
router.post('/admin/signup', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    const admin = yield Schema_1.Admin.findOne({ username });
    if (admin) {
        res.status(403).json({ message: "Admin already exists" });
    }
    else {
        const hashedPassword = yield bcryptjs_1.default.hash(password, 10);
        const newAdmin = new Schema_1.Admin({ username, password: hashedPassword });
        yield newAdmin.save();
        const token = jsonwebtoken_1.default.sign({ username }, SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: "Admin created successfully", token });
    }
}));
router.post('/admin/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    // It's more common to send credentials in the request body instead of headers
    const { username, password } = req.body; // Changed from req.headers to req.body
    if (typeof username === 'string' && typeof password === 'string') {
        const admin = yield Schema_1.Admin.findOne({ username });
        // Check if admin exists and admin.password is a string
        if (admin && admin.password && (yield bcryptjs_1.default.compare(password, admin.password))) {
            const token = jsonwebtoken_1.default.sign({ username }, SECRET, { expiresIn: '1h' });
            res.status(200).json({ message: "Admin logged in successfully", token });
        }
        else {
            res.status(403).json({ message: "Invalid username or password" });
        }
    }
    else {
        res.status(400).json({ message: "Bad request: Username and password must be provided as strings" });
    }
}));
router.post('/admin/courses', authenticateJwt, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { title, description, price, imageLink, published } = req.body;
    const course = yield Schema_1.Course.findOne({ title });
    if (course) {
        res.status(403).json({ message: "Course already exists" });
    }
    else {
        const newCourse = new Schema_1.Course({ title, description, price, imageLink, published });
        yield newCourse.save();
        res.status(200).json({ message: "Course created successfully", courseId: newCourse._id }); // in mongodb course id is automatically generated we jut have to retrieve it
    }
}));
router.put('/admin/courses/:courseId', authenticateJwt, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const course = yield Schema_1.Course.findByIdAndUpdate(req.params.courseId, req.body, { new: true });
    if (course) {
        res.json({ message: 'Course updated successfully', course });
    }
    else {
        res.status(404).json({ message: 'Course not found' });
    }
}));
router.delete('/admin/courses/:courseId', authenticateJwt, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const course = yield Schema_1.Course.findByIdAndDelete(req.params.courseId);
        if (!course) {
            return res.status(404).json({ message: 'Course not found' });
        }
        res.json({ message: 'Course deleted successfully' });
    }
    catch (error) {
        res.status(500).json({ message: 'Error deleting course' });
    }
}));
router.get('/admin/courses', authenticateJwt, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const courses = yield Schema_1.Course.find({ published: true });
    res.status(200).json({ message: "all the courses", courses });
}));
router.post('/users/signup', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    const user = yield Schema_1.User.findOne({ username });
    if (user) {
        res.status(403).json({ message: "User already exists" });
    }
    else {
        const hashedPassword = yield bcryptjs_1.default.hash(password, 10);
        const newUser = new Schema_1.User({ username, password: hashedPassword });
        yield newUser.save();
        const token = jsonwebtoken_1.default.sign({ username }, SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: "User created successfully", token });
    }
}));
router.post('/users/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const username = req.headers.username;
    const password = req.headers.password;
    if (typeof username === 'string' && typeof password === 'string') {
        const user = yield Schema_1.User.findOne({ username });
        // Check if user exists and user.password is not null or undefined
        if (user && user.password && (yield bcryptjs_1.default.compare(password, user.password))) {
            const token = jsonwebtoken_1.default.sign({ username }, SECRET, { expiresIn: '1h' });
            res.status(200).json({ message: "User logged in successfully", token });
        }
        else {
            res.status(403).json({ message: "Invalid username or password" });
        }
    }
    else {
        res.status(400).json({ message: "Bad request: Username and password must be provided as strings" });
    }
}));
router.get('/users/courses', authenticateJwt, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const courses = yield Schema_1.Course.find({ published: true });
    res.status(200).json({ message: "all the courses", courses });
}));
router.post('/users/courses/:courseId', authenticateJwt, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const course = yield Schema_1.Course.findById(req.params.courseId);
    if (course) {
        if (req.user && req.user.username) {
            const user = yield Schema_1.User.findOne({ username: req.user.username });
            if (user) {
                user.purchasedCourses.push(course._id);
                yield user.save();
                res.json({ message: 'Course purchased successfully' });
            }
            else {
                res.status(403).json({ message: 'User not found' });
            }
        }
        else {
            res.status(401).json({ message: 'Unauthorized' });
        }
    }
    else {
        res.status(404).json({ message: 'Course not found' });
    }
}));
router.get('/users/purchasedCourses', authenticateJwt, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    if (req.user && req.user.username) {
        const user = yield Schema_1.User.findOne({ username: req.user.username }).populate('purchasedCourses');
        if (user) {
            res.json({ purchasedCourses: user.purchasedCourses || [] });
        }
        else {
            res.status(403).json({ message: 'User not found' });
        }
    }
    else {
        res.status(401).json({ message: 'Unauthorized' });
    }
}));
exports.default = router;
