import { Controller, Get, Req, Res, Redirect, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { JwtPayload } from '../middleware/types';

// named api to match france connect post-login and post-logout redirection URL
@Controller('api')
export class AuthController {
  constructor(private authService: AuthService) {}

  // get the france connect authorization URL
  @Get('/authorization-url')
  @Redirect()
  franceConnectLogin(@Res() res) {
    try {
      const redirectData = this.authService.getFranceConnectAuthorizationURL();
      return {
        url: redirectData,
        statusCode: 302,
      };
    } catch (error) {
      res.status(500).send('Login failed, please try again later');
    }
  }

  // fance connect login redirection URI
  @Get('/login-callback')
  async franceConnectCallback(@Req() req, @Res() res): Promise<any> {
    try {
      const jwt = await this.authService.handleFranceConnectCallback(req.query);
      // we create a cookie to initiate user session in our application
      res.cookie('oidc', jwt, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
      });
      // redirect to home
      res.redirect('../');
    } catch (error) {
      res
        .status(401)
        .send(
          'Authentication with France Connect failed, please try again later',
        );
    }
  }

  // get the france connect logout URL
  @Get('/logout-url')
  @Redirect()
  @UseGuards(AuthGuard('jwt'))
  franceConnectLogout(@Req() req, @Res() res) {
    try {
      const jwtPayload: JwtPayload = req.user;
      const redirectData = this.authService.getFranceConnectLogoutURL(
        jwtPayload.idToken,
        jwtPayload.state,
      );
      // expire the cookie to end the user session in our application
      res.cookie('oidc', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        expires: new Date(0),
      });
      return {
        url: redirectData,
        statusCode: 302,
      };
    } catch (error) {
      res.status(500).send('Logout failed, please try again later');
    }
  }
}
