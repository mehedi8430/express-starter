import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import User from '@/models/User';
import { sendResponse, sendError } from '@/utils/apiResponse';
import catchAsync from '@/utils/catchAsync';

const generateToken = (id: string): string => {
  return jwt.sign({ id }, process.env.JWT_SECRET as string, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

export const register = catchAsync(async (req: Request, res: Response) => {
  const { name, email, password } = req.body;

  const userExists = await User.findOne({ email });
  if (userExists) {
    sendError(res, 400, 'User already exists');
    return;
  }

  const user = await User.create({
    name,
    email,
    password,
  });

  const token = generateToken(user._id.toString());

  sendResponse(res, 201, true, 'User registered successfully', {
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
    token,
  });
});

export const login = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.comparePassword(password))) {
    sendError(res, 401, 'Invalid credentials');
    return;
  }

  const token = generateToken(user._id.toString());

  sendResponse(res, 200, true, 'Login successful', {
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
    token,
  });
});

export const getProfile = catchAsync(async (req: Request, res: Response) => {
  const user = await User.findById(req.user?.id);

  if (!user) {
    sendError(res, 404, 'User not found');
    return;
  }

  sendResponse(res, 200, true, 'Profile retrieved successfully', {
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  });
});
