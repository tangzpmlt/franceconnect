import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { UserDto } from '../users/users.dto';
import fetch, { Response } from 'node-fetch';

import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';

jest.mock('node-fetch', () => ({
  default: jest.fn(),
  __esModule: true, // This tells Jest that we're mocking an ES module
}));

const mockFetchResponse = (data: any, ok = true) => {
  return Promise.resolve({
    ok,
    json: () => Promise.resolve(data),
    text: () =>
      Promise.resolve(typeof data === 'string' ? data : JSON.stringify(data)),
  } as Response);
};

describe('AuthServiceInitialisation', () => {
  let usersService: UsersService;
  let jwtService: JwtService;

  beforeEach(() => {
    usersService = new UsersService();
    jwtService = new JwtService();
  });

  it('should configure OIDC on service initialization', async () => {
    const mockOidcConfig = {
      authorization_endpoint: 'https://franceconnect.com',
    };
    fetch.mockImplementation(() => mockFetchResponse(mockOidcConfig));
    const authService = new AuthService(usersService, jwtService);
    await new Promise(process.nextTick);
    expect(authService['oidcConfiguration']).toEqual(mockOidcConfig);
  });
});

describe('AuthServiceLogic', () => {
  let authService: AuthService;
  let usersService: Partial<UsersService>;
  let jwtService: Partial<JwtService>;
  const profile1 = {
    sub: '1',
    email: 'tanguy@pommellet.com',
  };
  const user1: UserDto = { oidcId: '1', email: 'tanguy@pommellet.com' };
  const mockAccessToken = 'accessToken';
  const mockIdToken = 'idToken';
  const mockCode = 'code';
  const mockState = 'state';

  beforeEach(() => {
    process.env.FC_CONFIG_URL = 'https://franceconnect.com/config';
    process.env.LOGIN_REDIRECT_URI = 'https://api/login-redirect';
    process.env.CLIENT_ID = 'client-id';
    process.env.CLIENT_SECRET = 'client-secret';
    process.env.POST_LOGOUT_REDIRECT_URI = 'https://api/post-logout-redirect';

    usersService = {
      findUserById: jest.fn(),
      createUserFromProfile: jest.fn(),
    };
    jwtService = { verify: jest.fn(), sign: jest.fn() };

    // Spy and mock the initializeOIDCConfiguration method before instantiation
    const initializeSpy = jest.spyOn(
      AuthService.prototype,
      'initializeOIDCConfiguration',
    );
    initializeSpy.mockImplementation(() => Promise.resolve());

    // Now create the AuthService instance
    authService = new AuthService(
      usersService as UsersService,
      jwtService as JwtService,
    );

    initializeSpy.mockRestore();
    fetch.mockClear();
    jest.clearAllMocks();

    authService['oidcConfiguration'] = {
      authorization_endpoint: 'https://franceconnect.com/auth',
      end_session_endpoint: 'https://franceconnect.com/logout',
      token_endpoint: 'https://franceconnect.com/token',
      userinfo_endpoint: 'https://franceconnect.com/userinfo',
    } as any;
  });

  describe('initializeOIDCConfiguration', () => {
    it('should throw InternalServerErrorException on failure', async () => {
      fetch.mockImplementation(() => mockFetchResponse({}, false));
      await expect(authService.initializeOIDCConfiguration()).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('getFranceConnectAuthorizationURL', () => {
    it('should return a valid authorization URL', () => {
      const url = authService.getFranceConnectAuthorizationURL();
      // Check the start of the URL
      expect(
        url.startsWith(authService['oidcConfiguration'].authorization_endpoint),
      ).toBeTruthy();

      const urlObj = new URL(url);
      const queryParams = urlObj.searchParams;

      // Check 'state' parameter is present, is a hexadecimal, and length > 22
      const state = queryParams.get('state');
      expect(state).toMatch(/^[a-f0-9]+$/);
      expect(state!.length).toBeGreaterThan(22);

      // Check 'nonce' parameter is present, is a hexadecimal, and length > 22
      const nonce = queryParams.get('nonce');
      expect(nonce).toMatch(/^[a-f0-9]+$/);
      expect(nonce!.length).toBeGreaterThan(22);

      const responseType = queryParams.get('response_type');
      expect(responseType).toBe('code');

      const scope = queryParams.get('scope');
      expect(scope).toBe('openid email profile');
    });
  });

  describe('getFranceConnectLogoutURL', () => {
    it('should throw an error if null input', () => {
      expect(() => authService.getFranceConnectLogoutURL(null, null)).toThrow(
        InternalServerErrorException,
      );
    });
    it('should return a valid logout URL', () => {
      const url = authService.getFranceConnectLogoutURL(mockIdToken, mockState);
      // Check the start of the URL
      expect(
        url.startsWith(authService['oidcConfiguration'].end_session_endpoint),
      ).toBeTruthy();

      const urlObj = new URL(url);
      const queryParams = urlObj.searchParams;

      const state = queryParams.get('state');
      expect(state).toBe(mockState);

      const idToken = queryParams.get('id_token_hint');
      expect(idToken).toBe(mockIdToken);

      const logoutURI = queryParams.get('post_logout_redirect_uri');
      expect(logoutURI).toBe(process.env.POST_LOGOUT_REDIRECT_URI);
    });
  });

  describe('handleFranceConnectCallback', () => {
    it('should throw an UnauthorizedException error when one step fails', async () => {
      authService.validateCallbackQueryParams = jest
        .fn()
        .mockImplementation(() => {
          throw new Error();
        });
      await expect(
        authService.handleFranceConnectCallback({
          code: mockCode,
          state: mockState,
        }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should call generateJwt with the correct payload', async () => {
      authService.validateCallbackQueryParams = jest
        .fn()
        .mockReturnValue({ code: mockCode, state: mockState });
      authService.getTokensFromCode = jest.fn().mockResolvedValue({
        idToken: mockIdToken,
        accessToken: mockAccessToken,
      });
      authService.validateIdToken = jest.fn();
      authService.fetchOidcProfile = jest.fn().mockResolvedValue(profile1);
      authService.validateProfile = jest.fn().mockResolvedValue(undefined);
      authService.generateJwt = jest.fn().mockResolvedValue('jwtToken');

      await authService.handleFranceConnectCallback({
        code: mockCode,
        state: mockState,
      });

      expect(authService.generateJwt).toHaveBeenCalledWith({
        idToken: mockIdToken,
        state: mockState,
        oidcId: profile1.sub,
      });
    });
  });

  describe('validateCallbackQueryParams', () => {
    const validState = 'validState';
    const invalidState = 'invalidState';

    beforeEach(() => {
      authService['states'] = [validState];
    });

    it('should throw an error if query params are missing', () => {
      expect(() =>
        authService.validateCallbackQueryParams({ state: 'someState' }),
      ).toThrow('missing query params');

      expect(() =>
        authService.validateCallbackQueryParams({ code: 'someCode' }),
      ).toThrow('missing query params');
    });

    it('should throw an error if state is not known', () => {
      const query = { code: mockCode, state: invalidState };
      expect(() => authService.validateCallbackQueryParams(query)).toThrow(
        'unknown state',
      );
    });

    it('should remove the state from the list of states if valid params', () => {
      const query = {
        code: mockCode,
        state: validState,
      };
      const result = authService.validateCallbackQueryParams(query);
      expect(result).toEqual(query);
      expect(authService['states'].includes(validState)).toBeFalsy();
    });
  });

  describe('getTokensFromCode', () => {
    it('should throw an error if the code is null', async () => {
      await expect(authService.getTokensFromCode(null)).rejects.toThrow(
        'input is null or undefined',
      );
    });

    it('should call fetch with correct parameters and headers', async () => {
      const mockResponse = {
        access_token: mockAccessToken,
        id_token: mockIdToken,
      };
      fetch.mockImplementation(() => mockFetchResponse(mockResponse));
      const { idToken, accessToken } =
        await authService.getTokensFromCode(mockCode);
      expect(idToken).toEqual(mockIdToken);
      expect(accessToken).toEqual(mockAccessToken);

      const fetchCall = fetch.mock.calls[0];
      const fetchUrl = fetchCall[0];
      const fetchOptions = fetchCall[1];

      expect(fetchOptions.headers).toEqual({
        'Content-Type': 'application/x-www-form-urlencoded',
      });
      expect(fetchOptions.method).toBe('POST');

      const params = new URLSearchParams(fetchOptions.body);
      expect(fetchUrl).toBe('https://franceconnect.com/token');
      expect(params.get('grant_type')).toBe('authorization_code');
      expect(params.get('code')).toBe(mockCode);
      expect(params.get('redirect_uri')).toBe(process.env.LOGIN_REDIRECT_URI);
      expect(params.get('client_id')).toBe(process.env.CLIENT_ID);
      expect(params.get('client_secret')).toBe(process.env.CLIENT_SECRET);
    });

    it('should throw an Error when the fetch response is not ok', async () => {
      fetch.mockImplementation(() => mockFetchResponse({}, false));
      await expect(authService.getTokensFromCode(mockCode)).rejects.toThrow(
        Error,
      );
    });
  });

  describe('validateIdToken', () => {
    const validNonce = 'validNonce';
    const invalidNonce = 'invalidNonce';
    const invalidAud = 'invalidAud';
    const validHash = 'lKJ3bnvW9hFGK8Q0Thd3PA';
    const invalidHash = 'invalidHash';

    beforeEach(() => {
      authService['nonces'] = [validNonce];
    });

    it('should throw an error if idToken or accessToken is missing', () => {
      expect(() => authService.validateIdToken(null, mockAccessToken)).toThrow(
        'input is null or undefined',
      );
      expect(() => authService.validateIdToken(mockIdToken, null)).toThrow(
        'input is null or undefined',
      );
    });

    it('should throw an error if nonce is not in the nonces list', () => {
      jwtService.verify = jest.fn().mockReturnValue({
        nonce: invalidNonce,
        aud: process.env.CLIENT_ID,
        at_hash: validHash,
      });
      expect(() =>
        authService.validateIdToken(mockIdToken, mockAccessToken),
      ).toThrow('invalid nonce');
    });

    it('should throw an error if audience is different from clientId', () => {
      jwtService.verify = jest.fn().mockReturnValue({
        nonce: validNonce,
        aud: invalidAud,
        at_hash: validHash,
      });
      expect(() =>
        authService.validateIdToken(mockIdToken, mockAccessToken),
      ).toThrow('invalid audience');
    });

    it('should throw an error if at_hash validation fails', () => {
      jwtService.verify = jest.fn().mockReturnValue({
        nonce: validNonce,
        aud: process.env.CLIENT_ID,
        at_hash: invalidHash,
      });
      expect(() =>
        authService.validateIdToken(mockIdToken, mockAccessToken),
      ).toThrow('invalid at_hash');
    });

    it('should remove nonce from nonces list when validated successfully', () => {
      jwtService.verify = jest.fn().mockReturnValue({
        nonce: validNonce,
        aud: process.env.CLIENT_ID,
        at_hash: validHash,
      });
      expect(() =>
        authService.validateIdToken(mockIdToken, mockAccessToken),
      ).not.toThrow();
      expect(authService['nonces'].includes(validNonce)).toBeFalsy();
    });
  });

  describe('fetchOidcProfile', () => {
    it('should throw an error if accessToken is null', async () => {
      await expect(authService.fetchOidcProfile(null)).rejects.toThrow(
        'input is null or undefined',
      );
    });

    it('should call fetch with correct URL and headers', async () => {
      const mockJwtToken = 'jwtToken';

      fetch.mockImplementation(() => mockFetchResponse(mockJwtToken));
      jwtService.verify = jest.fn().mockReturnValue(profile1);

      const profile = await authService.fetchOidcProfile(mockAccessToken);
      expect(profile).toEqual(profile1);

      const fetchCall = fetch.mock.calls[0];
      const fetchUrl = fetchCall[0];
      const fetchOptions = fetchCall[1];

      expect(fetchUrl).toBe('https://franceconnect.com/userinfo');
      expect(fetchOptions.headers).toEqual({
        Authorization: `Bearer ${mockAccessToken}`,
      });
      expect(fetchOptions.method).toBe('GET');
    });

    it('should throw an Error when the fetch response is not ok', async () => {
      fetch.mockImplementation(() => mockFetchResponse({}, false));
      await expect(
        authService.fetchOidcProfile(mockAccessToken),
      ).rejects.toThrow(Error);
    });
  });

  describe('validateProfile', () => {
    it('should throw an error when oidcProfile is null', async () => {
      await expect(authService.validateProfile(null)).rejects.toThrow(
        'input is null or undefined',
      );
    });

    it('creates a new user when no existing user is found', async () => {
      usersService.findUserById = jest.fn().mockReturnValue(undefined);
      usersService.createUserFromProfile = jest.fn().mockResolvedValue(user1);

      const result = await authService.validateProfile(profile1);

      expect(usersService.findUserById).toHaveBeenCalledWith(profile1.sub);
      expect(usersService.createUserFromProfile).toHaveBeenCalledWith(profile1);
      expect(result).toEqual(user1);
    });

    it('does not create a new user when an existing user is found', async () => {
      usersService.findUserById = jest.fn().mockReturnValue(user1);
      usersService.createUserFromProfile = jest
        .fn()
        .mockResolvedValue(undefined);

      const result = await authService.validateProfile(profile1);
      expect(usersService.createUserFromProfile).not.toHaveBeenCalled();
      expect(result).toEqual(user1);
    });
  });

  describe('generateJwt', () => {
    it('should throw an InternalServerErrorException when jwtPayload is null', async () => {
      await expect(authService.generateJwt(null)).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should successfully generate JWT for valid payload', async () => {
      const payload = { oidcId: '1', idToken: 'token', state: 'state' };
      const expectedToken = 'token';
      jwtService.sign = jest.fn().mockResolvedValue(expectedToken);
      const result = await authService.generateJwt(payload);
      expect(result).toEqual(expectedToken);
      expect(jwtService.sign).toHaveBeenCalledWith(payload);
    });
  });
});
