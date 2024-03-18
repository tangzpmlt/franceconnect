import { Controller, Get, Req, UseGuards, Redirect } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { UsersService } from './users/users.service';

@Controller()
export class AppController {
  constructor(private readonly userService: UsersService) {}

  // home page
  @Get()
  @Redirect('index.html', 301)
  redirectRoot() {}

  // endpoint only accessible to logged users
  @Get('/protected')
  @UseGuards(AuthGuard('jwt'))
  async getProtectedResource(@Req() req) {
    const user = this.userService.findUserById(req.user.oidcId);
    return user;
  }
}
