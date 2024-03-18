import {
  Injectable,
  Logger,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { UserDto } from '../users/users.dto';
import fetch from 'node-fetch';
import { randomBytes } from 'crypto';
import { createHash } from 'crypto';
import {
  DecodedIdToken,
  TokensResponse,
  OIDCConfiguration,
  CallbackQuery,
  OidcProfile,
} from './types';
import { JwtPayload } from '../middleware/types';

@Injectable()
export class AuthService {
  private oidcConfiguration: OIDCConfiguration;
  private states: string[];
  private nonces: string[];
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {
    this.initializeOIDCConfiguration();
    // scrappy way to store and validate states and nonces
    this.states = [];
    this.nonces = [];
  }

  async initializeOIDCConfiguration() {
    try {
      const response = await fetch(process.env.FC_CONFIG_URL);
      if (!response.ok) {
        throw new Error(response.statusText);
      }
      this.oidcConfiguration = await response.json();
    } catch (error) {
      this.logger.error(
        'Failed to initialise OIDC configuration: ',
        error.message,
      );
      throw new InternalServerErrorException();
    }
  }

  getFranceConnectAuthorizationURL(): string {
    try {
      const state = randomBytes(22).toString('hex');
      const nonce = randomBytes(22).toString('hex');
      this.states.push(state);
      this.nonces.push(nonce);
      const params = new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        response_type: 'code',
        scope: 'openid email profile',
        redirect_uri: process.env.LOGIN_REDIRECT_URI,
        state: state,
        nonce: nonce,
        acr_values: 'eidas1',
      });
      // the scope elements should be seperated by a %20 instead of +
      const paramsString = params.toString().replace(/\+/g, '%20');
      const authorizationUrl =
        this.oidcConfiguration.authorization_endpoint + `?${paramsString}`;
      return authorizationUrl;
    } catch (error) {
      this.logger.error('Login request failed: ' + error.message);
      throw new InternalServerErrorException();
    }
  }

  getFranceConnectLogoutURL(idToken: string, state: string): string {
    try {
      if (!idToken || !state) {
        throw new Error('missing logout params');
      }
      const params = new URLSearchParams({
        id_token_hint: idToken,
        post_logout_redirect_uri: process.env.POST_LOGOUT_REDIRECT_URI,
        state: state,
      });
      const logoutUrl =
        this.oidcConfiguration.end_session_endpoint + '?' + params.toString();
      return logoutUrl;
    } catch (error) {
      this.logger.error('Logout request failed: ' + error.message);
      throw new InternalServerErrorException();
    }
  }

  // see doc https://docs.partenaires.franceconnect.gouv.fr/fs/technique/technique-oidc-flux/
  async handleFranceConnectCallback(query: CallbackQuery): Promise<string> {
    try {
      const { code, state } = this.validateCallbackQueryParams(query);
      const { idToken, accessToken } = await this.getTokensFromCode(code);
      this.validateIdToken(idToken, accessToken);
      const oicfProfile: OidcProfile = await this.fetchOidcProfile(accessToken);
      await this.validateProfile(oicfProfile);
      return this.generateJwt({
        idToken: idToken,
        state: state,
        oidcId: oicfProfile.sub,
      });
    } catch (error) {
      this.logger.error('Authentication failed: ' + error.message);
      throw new UnauthorizedException();
    }
  }

  // validate the redirection from france connect
  validateCallbackQueryParams(query: any): { code: string; state: string } {
    try {
      const { code, state } = query;
      if (!code || !state) {
        throw new Error('missing query params');
      }
      const indexToRemove = this.states.findIndex((item) => item === state);
      if (indexToRemove !== -1) {
        this.states.splice(indexToRemove, 1);
      } else {
        throw new Error('unknown state');
      }
      return { code, state };
    } catch (error) {
      throw new Error(
        `cannot validate authentication callback, ${error.message}`,
      );
    }
  }

  // exhange code for tokens
  async getTokensFromCode(code: string): Promise<TokensResponse> {
    try {
      if (!code) {
        throw new Error('input is null or undefined');
      }
      const tokenEndpoint = this.oidcConfiguration.token_endpoint;
      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: process.env.LOGIN_REDIRECT_URI,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
      });
      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      });
      if (!response.ok) {
        throw new Error(response.statusText);
      }
      const tokenPayload = await response.json();
      return {
        idToken: tokenPayload.id_token,
        accessToken: tokenPayload.access_token,
      };
    } catch (error) {
      throw new Error(`cannot exchange code for tokens, ${error.message}`);
    }
  }

  // validate tokens from france connect
  validateIdToken(idToken: string, accessToken: string): void {
    try {
      if (!idToken || !accessToken) {
        throw new Error('input is null or undefined');
      }
      const decodedToken: DecodedIdToken = this.jwtService.verify(idToken, {
        secret: process.env.CLIENT_SECRET,
      });

      // nonce validation: should equal nonce stored in our db
      const nonce = decodedToken.nonce;
      const indexToRemove = this.nonces.findIndex((item) => item === nonce);
      if (indexToRemove !== -1) {
        this.nonces.splice(indexToRemove, 1);
      } else {
        throw new Error('invalid nonce');
      }

      // audience validation: should equal client id
      if (decodedToken.aud !== process.env.CLIENT_ID) {
        throw new Error('invalid audience');
      }

      // at_hash validation: should equal base64 URL-encoded SHA-256 hash's left-most half of the access token.
      const hash = createHash('sha256').update(accessToken).digest();
      const leftMostHalfBuffer = Uint8Array.prototype.slice.call(
        hash,
        0,
        hash.length / 2,
      );
      const leftMostHalf = Buffer.from(leftMostHalfBuffer)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      if (leftMostHalf !== decodedToken.at_hash) {
        throw new Error('invalid at_hash');
      }
    } catch (error) {
      throw new Error(`cannot validate id_token, ${error.message}`);
    }
  }

  // fetch user info from fance connect
  async fetchOidcProfile(accessToken: string): Promise<OidcProfile> {
    try {
      if (!accessToken) {
        throw new Error('input is null or undefined');
      }
      const userInfoEndpoint = this.oidcConfiguration.userinfo_endpoint;
      const response = await fetch(userInfoEndpoint, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      if (!response.ok) {
        throw new Error(response.statusText);
      }
      const jwtToken = await response.text();
      const oidcProfile = this.jwtService.verify(jwtToken, {
        secret: process.env.CLIENT_SECRET,
      }) as OidcProfile;
      return oidcProfile;
    } catch (error) {
      throw new Error(`cannot fetch user info, ${error.message}`);
    }
  }

  // turns the oidc profile into a user in our application
  async validateProfile(oidcProfile: OidcProfile): Promise<UserDto> {
    if (!oidcProfile) {
      throw new Error('cannot validate profile, input is null or undefined');
    }
    let user = this.usersService.findUserById(oidcProfile.sub);
    if (!user) {
      user = await this.usersService.createUserFromProfile(oidcProfile);
    }
    return user;
  }

  async generateJwt(jwtPayload: JwtPayload): Promise<string> {
    try {
      if (!jwtPayload) {
        throw new Error('input is null or undefined');
      }
      return this.jwtService.sign(jwtPayload);
    } catch (error) {
      this.logger.error('Jwt generation failed, ' + error.message);
      throw new InternalServerErrorException();
    }
  }
}
