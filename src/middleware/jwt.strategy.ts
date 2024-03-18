import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { Request } from 'express';
import { UsersService } from '../users/users.service';
import { JwtPayload } from './types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);
  constructor(private readonly usersService: UsersService) {
    super({
      // we store the jwt in a cookie
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request): string | null => {
          const token = request?.cookies?.oidc;
          return token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: JwtPayload): Promise<JwtPayload> {
    try {
      const user = await this.usersService.findUserById(payload.oidcId);
      if (!user) {
        throw new Error(`no user found for oidcId: ${payload.oidcId}`);
      }
      return payload;
    } catch (error) {
      this.logger.error(`Jwt validation failed: ${error.message}`);
      throw new UnauthorizedException();
    }
  }
}
