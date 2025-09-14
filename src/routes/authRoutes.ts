import { Router } from 'express';
import { body } from 'express-validator';
import { register, login, getProfile } from '@/controllers/authController';
import { protect } from '@/middleware/auth';
import { validate } from '@/middleware/validation';

const router = Router();

router.post(
  '/register',
  [
    body('name').trim().isLength({ min: 2 }).withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters'),
  ],
  validate,
  register
);

router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').exists().withMessage('Password is required'),
  ],
  validate,
  login
);

router.get('/profile', protect, getProfile);

export default router;
