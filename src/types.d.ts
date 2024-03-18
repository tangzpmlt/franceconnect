import 'express-session';
import { JwtPayload } from './middleware/types.ts';

declare module 'express-session' {
  interface SessionData {
    state?: string;
    nonce?: string;
  }
}

declare global {
  namespace Express {
    interface Request {
      User: JwtPayload;
    }
  }
}
