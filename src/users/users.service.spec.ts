import { UsersService } from './users.service';
import { OidcProfile } from '../auth/types';

describe('UsersService', () => {
  let service: UsersService;

  beforeEach(() => {
    service = new UsersService();
  });

  describe('createUserFromProfile', () => {
    it('should create a new User from a valid OidcProfile', async () => {
      const oidcProfile: OidcProfile = {
        sub: '1',
        email: 'tanguy@pommellet.com',
        family_name: 'Pommellet',
        given_name: 'Tanguy',
        preferred_username: 'tang',
        gender: 'male',
        birthdate: '1990-01-01',
      };

      const user = await service.createUserFromProfile(oidcProfile);

      expect(user.oidcId).toBe(oidcProfile.sub);
      expect(user.email).toBe(oidcProfile.email);
      expect(user.familyName).toBe(oidcProfile.family_name);
      expect(user.givenName).toBe(oidcProfile.given_name);
      expect(user.preferredUsername).toBe(oidcProfile.preferred_username);
      expect(user.gender).toBe(oidcProfile.gender);
      expect(user.birthdate).toBe(oidcProfile.birthdate);
    });

    it('should handle undefined values', async () => {
      const oidcProfile: OidcProfile = {
        sub: '1',
        email: 'tanguy@pommellet.com',
        family_name: undefined,
      };

      const user = await service.createUserFromProfile(oidcProfile);

      expect(user.oidcId).toBe(oidcProfile.sub);
      expect(user.familyName).toBeUndefined();
      expect(user.preferredUsername).toBeUndefined();
    });

    it('should throw an error if missing sub', async () => {
      const oidcProfile: OidcProfile = {
        sub: undefined,
      };

      await expect(service.createUserFromProfile(oidcProfile)).rejects.toThrow(
        'Wrong user format',
      );
    });
  });

  describe('findUserById', () => {
    beforeEach(() => {
      const oidcProfile: OidcProfile = {
        sub: '1',
        email: 'tanguy@pommellet.com',
      };
      service.createUserFromProfile(oidcProfile);
    });
    it('should find a user by oidcId', () => {
      const foundUser = service.findUserById('1');
      expect(foundUser).toBeDefined();
    });

    it('should return undefined when no user with the given oidcId exists', () => {
      const foundUser = service.findUserById('2');
      expect(foundUser).toBeUndefined();
    });
  });
});
