# Express + MongoDB + TypeScript + Bun Production-Ready Project Setup

## Prerequisites

1. Install Bun (if not already installed):

```bash
curl -fsSL https://bun.sh/install | bash
```

2. Ensure MongoDB is installed locally or have a MongoDB Atlas connection string ready

## Step 1: Initialize Project

```bash
# Create project directory
mkdir my-express-app
cd my-express-app

# Initialize with Bun
bun init
```

## Step 2: Install Dependencies

```bash
# Production dependencies
bun add express mongoose cors helmet morgan compression dotenv
bun add express-rate-limit express-validator bcryptjs jsonwebtoken
bun add winston winston-daily-rotate-file

# Development dependencies
bun add -d @types/express @types/node @types/cors @types/morgan
bun add -d @types/compression @types/bcryptjs @types/jsonwebtoken
bun add -d typescript nodemon concurrently ts-node-dev
bun add -d @typescript-eslint/eslint-plugin @typescript-eslint/parser
bun add -d eslint prettier eslint-config-prettier eslint-plugin-prettier
```

## Step 3: TypeScript Configuration

Create `tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noImplicitThis": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "moduleResolution": "node",
    "baseUrl": "./",
    "paths": {
      "@/*": ["src/*"],
      "@/config/*": ["src/config/*"],
      "@/controllers/*": ["src/controllers/*"],
      "@/models/*": ["src/models/*"],
      "@/routes/*": ["src/routes/*"],
      "@/middleware/*": ["src/middleware/*"],
      "@/utils/*": ["src/utils/*"],
      "@/types/*": ["src/types/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "**/*.test.ts", "**/*.spec.ts"]
}
```

## Step 4: ESLint and Prettier Configuration

Create `.eslintrc.json`:

```json
{
  "env": {
    "node": true,
    "es2021": true
  },
  "extends": [
    "eslint:recommended",
    "@typescript-eslint/recommended",
    "prettier"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": 12,
    "sourceType": "module"
  },
  "plugins": ["@typescript-eslint", "prettier"],
  "rules": {
    "prettier/prettier": "error",
    "@typescript-eslint/no-unused-vars": "error",
    "@typescript-eslint/explicit-function-return-type": "warn"
  }
}
```

Create `.prettierrc`:

```json
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 80,
  "tabWidth": 2,
  "useTabs": false
}
```

## Step 5: Environment Configuration

Create `.env`:

```env
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/myapp
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRE=7d
BCRYPT_SALT_ROUNDS=12

# Rate limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS
CORS_ORIGIN=http://localhost:3000
```

Create `.env.example`:

```env
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/myapp
JWT_SECRET=
JWT_EXPIRE=7d
BCRYPT_SALT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
CORS_ORIGIN=http://localhost:3000
```

## Step 6: Project Structure

Create the following directory structure:

```
src/
├── config/
│   ├── database.ts
│   └── logger.ts
├── controllers/
│   ├── authController.ts
│   └── userController.ts
├── middleware/
│   ├── auth.ts
│   ├── errorHandler.ts
│   └── validation.ts
├── models/
│   └── User.ts
├── routes/
│   ├── authRoutes.ts
│   ├── userRoutes.ts
│   └── index.ts
├── types/
│   ├── express.d.ts
│   └── index.ts
├── utils/
│   ├── apiResponse.ts
│   ├── catchAsync.ts
│   └── validators.ts
├── app.ts
└── server.ts
```

## Step 7: Core Configuration Files

### Database Configuration (`src/config/database.ts`)

```typescript
import mongoose from 'mongoose';
import logger from './logger';

const connectDB = async (): Promise<void> => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI as string, {
      // Remove deprecated options as they're now defaults in Mongoose 6+
    });

    logger.info(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    logger.error('Database connection failed:', error);
    process.exit(1);
  }
};

export default connectDB;
```

### Logger Configuration (`src/config/logger.ts`)

```typescript
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: logFormat,
  defaultMeta: { service: 'express-app' },
  transports: [
    new DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxFiles: '14d',
    }),
    new DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxFiles: '14d',
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    })
  );
}

export default logger;
```

## Step 8: Types and Interfaces

### Express Types (`src/types/express.d.ts`)

```typescript
import { JwtPayload } from 'jsonwebtoken';

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}
```

### Common Types (`src/types/index.ts`)

```typescript
export interface IUser {
  _id: string;
  email: string;
  password: string;
  name: string;
  role: 'user' | 'admin';
  createdAt: Date;
  updatedAt: Date;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
}
```

## Step 9: Models

### User Model (`src/models/User.ts`)

```typescript
import mongoose, { Document, Schema } from 'mongoose';
import bcrypt from 'bcryptjs';
import { IUser } from '@/types';

export interface IUserDocument extends IUser, Document {
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUserDocument>(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      maxlength: [50, 'Name cannot exceed 50 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      match: [
        /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
        'Please enter a valid email',
      ],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [6, 'Password must be at least 6 characters'],
      select: false,
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
  },
  {
    timestamps: true,
  }
);

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12');
  this.password = await bcrypt.hash(this.password, saltRounds);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

export default mongoose.model<IUserDocument>('User', userSchema);
```

## Step 10: Utilities

### API Response (`src/utils/apiResponse.ts`)

```typescript
import { Response } from 'express';
import { ApiResponse } from '@/types';

export const sendResponse = <T>(
  res: Response,
  statusCode: number,
  success: boolean,
  message: string,
  data?: T
): Response => {
  const response: ApiResponse<T> = {
    success,
    message,
    ...(data && { data }),
  };

  return res.status(statusCode).json(response);
};

export const sendError = (
  res: Response,
  statusCode: number,
  message: string,
  error?: string
): Response => {
  const response: ApiResponse = {
    success: false,
    message,
    ...(error && { error }),
  };

  return res.status(statusCode).json(response);
};
```

### Async Error Handler (`src/utils/catchAsync.ts`)

```typescript
import { Request, Response, NextFunction } from 'express';

type AsyncFunction = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<any>;

const catchAsync = (fn: AsyncFunction) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

export default catchAsync;
```

## Step 11: Middleware

### Authentication Middleware (`src/middleware/auth.ts`)

```typescript
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { sendError } from '@/utils/apiResponse';
import User from '@/models/User';

export const protect = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    let token: string | undefined;

    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      sendError(res, 401, 'Access denied. No token provided.');
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as any;
    const user = await User.findById(decoded.id);

    if (!user) {
      sendError(res, 401, 'Token is not valid');
      return;
    }

    req.user = decoded;
    next();
  } catch (error) {
    sendError(res, 401, 'Token is not valid');
  }
};

export const authorize = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !roles.includes(req.user.role)) {
      sendError(res, 403, 'Access denied. Insufficient permissions.');
      return;
    }
    next();
  };
};
```

### Error Handler (`src/middleware/errorHandler.ts`)

```typescript
import { Request, Response, NextFunction } from 'express';
import logger from '@/config/logger';
import { sendError } from '@/utils/apiResponse';

interface CustomError extends Error {
  statusCode?: number;
  code?: number;
  keyValue?: any;
  errors?: any;
}

const errorHandler = (
  err: CustomError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let error = { ...err };
  error.message = err.message;

  // Log error
  logger.error(err);

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = { ...error, statusCode: 404, message };
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const message = 'Duplicate field value entered';
    error = { ...error, statusCode: 400, message };
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors || {})
      .map((val: any) => val.message)
      .join(', ');
    error = { ...error, statusCode: 400, message };
  }

  sendError(res, error.statusCode || 500, error.message || 'Server Error');
};

export default errorHandler;
```

## Step 12: Controllers

### Auth Controller (`src/controllers/authController.ts`)

```typescript
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
```

## Step 13: Routes

### Auth Routes (`src/routes/authRoutes.ts`)

```typescript
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
```

### Main Routes (`src/routes/index.ts`)

```typescript
import { Router } from 'express';
import authRoutes from './authRoutes';

const router = Router();

router.use('/auth', authRoutes);

// Health check
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
  });
});

export default router;
```

## Step 14: Validation Middleware (`src/middleware/validation.ts`)

```typescript
import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';
import { sendError } from '@/utils/apiResponse';

export const validate = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const errorMessages = errors
      .array()
      .map((error) => error.msg)
      .join(', ');

    sendError(res, 400, 'Validation failed', errorMessages);
    return;
  }

  next();
};
```

## Step 15: Main Application (`src/app.ts`)

```typescript
import express, { Application, Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import routes from './routes';
import errorHandler from './middleware/errorHandler';
import logger from './config/logger';

const app: Application = express();

// Security middleware
app.use(helmet());

// CORS
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.',
  },
});
app.use('/api', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression middleware
app.use(compression());

// Logging middleware
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
} else {
  app.use(
    morgan('combined', {
      stream: { write: (message) => logger.info(message.trim()) },
    })
  );
}

// Routes
app.use('/api/v1', routes);

// 404 handler
app.all('*', (req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
  });
});

// Error handling middleware
app.use(errorHandler);

export default app;
```

## Step 16: Server Entry Point (`src/server.ts`)

```typescript
import { config } from 'dotenv';

// Load environment variables first
config();

import app from './app';
import connectDB from './config/database';
import logger from './config/logger';

const PORT = process.env.PORT || 3000;

// Handle uncaught exceptions
process.on('uncaughtException', (err: Error) => {
  logger.error('Uncaught Exception:', err);
  process.exit(1);
});

// Connect to database
connectDB();

const server = app.listen(PORT, () => {
  logger.info(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err: Error) => {
  logger.error('Unhandled Rejection:', err);
  server.close(() => {
    process.exit(1);
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received');
  server.close(() => {
    logger.info('Process terminated');
  });
});
```

## Step 17: Package.json Scripts

Update your `package.json` scripts:

```json
{
  "scripts": {
    "dev": "bun run --watch src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "start:prod": "NODE_ENV=production node dist/server.js",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "format": "prettier --write src/**/*.ts",
    "type-check": "tsc --noEmit"
  }
}
```

## Step 18: Additional Configuration Files

### `.gitignore`

```
node_modules/
dist/
.env
logs/
*.log
.DS_Store
coverage/
.nyc_output/
```

### `.dockerignore` (Optional)

```
node_modules
dist
.env
.git
.gitignore
README.md
Dockerfile
.dockerignore
```

### `Dockerfile` (Optional)

```dockerfile
FROM oven/bun:1 as base
WORKDIR /usr/src/app

# Install dependencies into temp directory
FROM base AS install
RUN mkdir -p /temp/dev
COPY package.json bun.lockb /temp/dev/
RUN cd /temp/dev && bun install --frozen-lockfile

RUN mkdir -p /temp/prod
COPY package.json bun.lockb /temp/prod/
RUN cd /temp/prod && bun install --frozen-lockfile --production

# Copy node_modules from temp directory
FROM base AS prerelease
COPY --from=install /temp/dev/node_modules node_modules
COPY . .

ENV NODE_ENV=production
RUN bun run build

# Copy production dependencies and source code into final image
FROM base AS release
COPY --from=install /temp/prod/node_modules node_modules
COPY --from=prerelease /usr/src/app/dist dist
COPY --from=prerelease /usr/src/app/package.json .

USER bun
EXPOSE 3000/tcp
ENTRYPOINT [ "bun", "run", "start:prod" ]
```

## Step 19: Running the Application

1. **Start MongoDB** (if running locally):

```bash
mongod
```

2. **Copy environment variables**:

```bash
cp .env.example .env
# Edit .env with your actual values
```

3. **Run in development**:

```bash
bun run dev
```

4. **Build for production**:

```bash
bun run build
bun run start:prod
```

## Step 20: Testing the API

Test your endpoints:

```bash
# Register a user
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","password":"password123"}'

# Get profile (replace TOKEN with actual token)
curl -X GET http://localhost:3000/api/v1/auth/profile \
  -H "Authorization: Bearer TOKEN"
```

## Additional Best Practices

1. **Add input sanitization** with `express-mongo-sanitize`
2. **Add API documentation** with Swagger/OpenAPI
3. **Implement comprehensive logging**
4. **Add health checks and monitoring**
5. **Set up CI/CD pipeline**
6. **Add comprehensive testing** with Jest or Vitest
7. **Implement caching** with Redis
8. **Add database indexing** for performance
9. **Set up monitoring** with tools like New Relic or DataDog
10. **Implement proper secrets management**

This setup provides a solid, production-ready foundation for your Express.js application with MongoDB, TypeScript, and Bun!
