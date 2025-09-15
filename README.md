# express-starter

To install dependencies:

```bash
bun install
```

## Running the Application

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

This project was created using `bun init` in bun v1.2.21. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.
