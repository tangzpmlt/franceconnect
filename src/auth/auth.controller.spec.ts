import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: AuthService;
  const resMock = {
    cookie: jest.fn(),
    redirect: jest.fn(),
    status: jest.fn().mockReturnThis(),
    send: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            handleFranceConnectCallback: jest.fn(),
            getFranceConnectAuthorizationURL: jest.fn(),
            getFranceConnectLogoutURL: jest.fn(),
          },
        },
      ],
    })
      // bypass the passport strategy
      .overrideGuard(AuthGuard('jwt'))
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);

    jest.clearAllMocks();
  });

  describe('franceConnectLogin', () => {
    it('should return a France Connect authorization URL with a 302 status code', () => {
      const mockAuthorizationUrl = 'https://france-connect/auth';
      authService.getFranceConnectAuthorizationURL = jest
        .fn()
        .mockReturnValue(mockAuthorizationUrl);

      const result = controller.franceConnectLogin(resMock);

      expect(result).toEqual({
        url: mockAuthorizationUrl,
        statusCode: 302,
      });
    });

    it('should send a 500 status code on failed login url generation', async () => {
      authService.getFranceConnectAuthorizationURL = jest
        .fn()
        .mockImplementation(() => {
          throw new UnauthorizedException();
        });

      await controller.franceConnectLogin(resMock);

      expect(resMock.status).toHaveBeenCalledWith(500);
      expect(resMock.send).toHaveBeenCalledWith(
        'Login failed, please try again later',
      );
    });
  });

  describe('franceConnectCallback', () => {
    const reqMock = {
      query: { code: 'code', state: 'state' },
    };
    it('should set a cookie and redirect on successful authentication', async () => {
      const jwtMock = 'jwtTokenMock';
      authService.handleFranceConnectCallback = jest
        .fn()
        .mockResolvedValue(jwtMock);

      await controller.franceConnectCallback(reqMock, resMock);

      expect(resMock.cookie).toHaveBeenCalledWith('oidc', jwtMock, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
      });
      expect(resMock.redirect).toHaveBeenCalledWith('../');
    });

    it('should send a 401 status code on failed authentication', async () => {
      authService.handleFranceConnectCallback = jest
        .fn()
        .mockImplementation(() => {
          throw new UnauthorizedException();
        });

      await controller.franceConnectCallback(reqMock, resMock);

      expect(resMock.status).toHaveBeenCalledWith(401);
      expect(resMock.send).toHaveBeenCalledWith(
        'Authentication with France Connect failed, please try again later',
      );
    });
  });

  describe('franceConnectLogout', () => {
    const reqMock = {
      user: { oidcId: '1', idToken: 'token', state: 'state' },
    };
    it('should expire the oidc cookie and redirect to the France Connect logout URL', async () => {
      authService.getFranceConnectLogoutURL = jest
        .fn()
        .mockReturnValue('https://logout.url');

      const result = await controller.franceConnectLogout(reqMock, resMock);

      expect(result.url).toBe('https://logout.url');
      expect(result.statusCode).toBe(302);

      expect(resMock.cookie).toHaveBeenCalledWith('oidc', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        expires: expect.any(Date),
      });
      const expiresDate = resMock.cookie.mock.calls[0][2].expires;
      expect(expiresDate.getTime()).toBeLessThan(Date.now());
    });

    it('should send a 500 status code on failed logout url generation', async () => {
      authService.getFranceConnectLogoutURL = jest
        .fn()
        .mockImplementation(() => {
          throw new UnauthorizedException();
        });

      await controller.franceConnectLogout(reqMock, resMock);

      expect(resMock.status).toHaveBeenCalledWith(500);
      expect(resMock.send).toHaveBeenCalledWith(
        'Logout failed, please try again later',
      );
    });
  });
});
