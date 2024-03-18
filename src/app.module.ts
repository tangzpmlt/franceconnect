import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { ServeStaticModule } from '@nestjs/serve-static';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { PassportModule } from '@nestjs/passport';
import { join } from 'path';
import { JwtStrategy } from './middleware/jwt.strategy';

@Module({
  imports: [
    AuthModule,
    UsersModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    // set the static files directory
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'public'),
    }),
  ],
  controllers: [AppController],
  providers: [JwtStrategy],
})
export class AppModule {}
