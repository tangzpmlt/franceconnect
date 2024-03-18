import { Injectable } from '@nestjs/common';
import { UserDto } from './users.dto';
import { OidcProfile } from '../auth/types';
import { validate } from 'class-validator';

@Injectable()
export class UsersService {
  // this replace a proper db which would store user info
  private readonly users: UserDto[] = [];

  async createUserFromProfile(oidcProfile: OidcProfile): Promise<UserDto> {
    const user = new UserDto({
      oidcId: oidcProfile.sub,
      email: oidcProfile.email,
      familyName: oidcProfile.family_name,
      givenName: oidcProfile.given_name,
      preferredUsername: oidcProfile.preferred_username,
      gender: oidcProfile.gender,
      birthdate: oidcProfile.birthdate,
    });
    // validate that there is a oidcId
    const errors = await validate(user);
    if (errors.length > 0) {
      throw new Error(`Wrong user format: ${user}}`);
    }
    this.users.push(user);
    return user;
  }

  findUserById(oidcId: string): UserDto | undefined {
    return this.users.find((user) => user.oidcId === oidcId);
  }
}
