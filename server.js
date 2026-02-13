const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); // สำหรับเข้ารหัส Password
require('dotenv').config();
// --- Setup ---
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_DIR));
// --- Database ---
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});
// --- File Upload ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });
// --- Auth Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};
const authorizeRole = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
};
// --- API Routes ---
// 1. REGISTER (ลงทะเบียนสมาชิกใหม่) - *NEW*
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'กรุณากรอก Username และ Password' });
    }
    try {
        // ตรวจสอบว่ามี User นี้หรือยัง
        const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Username นี้ถูกใช้งานแล้ว' });
        }
        // เข้ารหัสรหัสผ่าน (Hash)
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        // บันทึกลงฐานข้อมูล (Default Role = user)
        await pool.query(
            'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)',
            [username, passwordHash, 'user']
        );
        res.status(201).json({ message: 'ลงทะเบียนสำเร็จ' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Server error during registration' });
    }
});
// 2. LOGIN (เข้าสู่ระบบ)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (rows.length === 0) return res.status(401).json({ error: 'ไม่พบผู้ใช้งานนี้' });
        const user = rows[0];
        
        // ตรวจสอบรหัสผ่าน (รองรับทั้ง Hash และแบบ Plain Text ชั่วคราวสำหรับ Admin เริ่มต้น)
        let match = false;
        if (username === 'admin' && password === 'admin1234') {
             match = true; // Backdoor ชั่วคราวสำหรับ Admin แรกเริ่ม
        } else {
             match = await bcrypt.compare(password, user.password_hash);
        }
        if (!match) return res.status(401).json({ error: 'รหัสผ่านไม่ถูกต้อง' });
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '8h' }
        );
        
        res.json({ 
            token, 
            user: { id: user.id, username: user.username, role: user.role } 
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// 3. GET CURRENT USER (เช็คสิทธิ์จาก Token)
app.get('/api/me', authenticateToken, (req, res) => {
    res.json(req.user);
});
// 4. UPLOAD FILE
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ filePath: `/uploads/${req.file.filename}` });
});
// 5. PROFILES CRUD (จัดการข้อมูลทำเนียบรุ่น)
// Helper function แปลงข้อมูล
const toDb = (d) => ({
    photo_path: d.photoUrl, signature_path: d.signatureUrl,
    military_id: d.militaryId, rank: d.rank, first_name: d.firstName, last_name: d.lastName,
    nickname: d.nickname, corps: d.corps, position: d.position, unit: d.unit,
    birth_date: d.birthDate || null, retirement_year: d.retirementYear,
    phone1: d.phone1, phone2: d.phone2, email: d.email, line_id: d.lineId,
    status: d.status, children_male: d.childrenMale || 0, children_female: d.childrenFemale || 0,
    house_no: d.houseNo, soi: d.soi, road: d.road, subdistrict: d.subdistrict,
    district: d.district, province: d.province, zip_code: d.zipCode
});
// Get All
app.get('/api/profiles', async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT 
                id, photo_path as "photoUrl", signature_path as "signatureUrl",
                military_id as "militaryId", rank, first_name as "firstName", last_name as "lastName", 
                nickname, corps, position, unit, to_char(birth_date, 'YYYY-MM-DD') as "birthDate", 
                retirement_year as "retirementYear", phone1, phone2, email, line_id as "lineId", 
                status, children_male as "childrenMale", children_female as "childrenFemale", 
                house_no as "houseNo", soi, road, subdistrict, district, province, zip_code as "zipCode",
                updated_at
            FROM profiles ORDER BY id ASC`);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});
// Create (ต้อง Login ก่อน)
app.post('/api/profiles', authenticateToken, async (req, res) => {
    const d = toDb(req.body);
    const fields = Object.keys(d);
    const values = Object.values(d);
    const placeholders = values.map((_, i) => `$${i + 1}`).join(',');
    try {
        await pool.query(`INSERT INTO profiles (${fields.join(',')}) VALUES (${placeholders})`, values);
        io.emit('data_updated'); 
        res.status(201).json({ message: 'Created' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});
// Update (ต้อง Login ก่อน)
app.put('/api/profiles/:id', authenticateToken, async (req, res) => {
    const id = req.params.id;
    const d = toDb(req.body);
    const setClause = Object.keys(d).map((key, i) => `${key}=$${i + 1}`).join(',');
    const values = [...Object.values(d), id];
    try {
        await pool.query(`UPDATE profiles SET ${setClause}, updated_at=CURRENT_TIMESTAMP WHERE id=$${values.length}`, values);
        io.emit('data_updated');
        res.json({ message: 'Updated' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});
// Delete (เฉพาะ Admin)
app.delete('/api/profiles/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        await pool.query('DELETE FROM profiles WHERE id = $1', [req.params.id]);
        io.emit('data_updated');
        res.json({ message: 'Deleted' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});
// Start Server
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
