import express from 'express';
import { getUser, register, login, logout } from '../controller/Users.js';
import { verifyToken } from '../middleware/verifyToken.js';
import { refreshToken } from '../controller/RefreshToken.js';

const router = express.Router();

router.get('/users', verifyToken, getUser);
router.post('/users', register);
router.post('/login', login);
router.delete('/logout', logout);

router.get('/token', refreshToken);

export default router;