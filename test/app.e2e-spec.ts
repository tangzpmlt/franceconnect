import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { UsersService } from '../src/users/users.service';
import { AuthService } from '../src/auth/auth.service';
import { OidcProfile } from '../src/auth/types';
import { UserDto } from 'src/users/users.dto';
import * as cookieParser from 'cookie-parser';
import * as dotenv from 'dotenv';

dotenv.config();

describe('AppController (e2e)', () => {
  let app: INestApplication;
  let userService: UsersService;
  let authService: AuthService;
  let user: UserDto;
  const profile: OidcProfile = {
    sub: '1',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = module.createNestApplication();
    app.use(cookieParser());

    userService = module.get<UsersService>(UsersService);
    authService = module.get<AuthService>(AuthService);

    // create a user in the db
    user = await userService.createUserFromProfile(profile);
    await app.init();
  });

  it('accesses client', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(301)
      .expect('Location', 'index.html');
  });

  it('accesses a protected route', async () => {
    const jwt = await authService.generateJwt({
      oidcId: user.oidcId,
      idToken: 'token',
      state: 'state',
    });
    await request(app.getHttpServer())
      .get('/protected')
      .set('cookie', `oidc=${jwt}`)
      .expect(200);
  });

  it('cannot access a protected route', async () => {
    const jwt = await authService.generateJwt({
      oidcId: '2',
      idToken: 'token',
      state: 'state',
    });
    await request(app.getHttpServer())
      .get('/protected')
      .set('cookie', `oidc=${jwt}`)
      .expect(401);
  });
});
