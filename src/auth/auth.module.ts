import { Module } from '@nestjs/common';
import { UsersModule } from '../users/users.module';
import { AuthService } from './auth.service';
import { HttpModule } from '@nestjs/axios';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import * as dotenv from 'dotenv';

// we need to access process.env.JWT_SECRET in the module initialization
dotenv.config();

@Module({
  imports: [
    UsersModule,
    HttpModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      // defines the session validity in our application
      signOptions: { expiresIn: '3d' },
    }),
  ],
  providers: [AuthService],
  controllers: [AuthController],
})
export class AuthModule {}
