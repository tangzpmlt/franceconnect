import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
} from 'class-validator';

// we could add other attributes if needed
export class UserDto {
  // we identify users internally by their oidcId for the sake of simplicity
  @IsNotEmpty()
  oidcId: string;

  @IsEmail()
  @IsOptional()
  email?: string;

  @IsOptional()
  @IsString()
  familyName?: string;

  @IsOptional()
  @IsString()
  givenName?: string;

  @IsOptional()
  @IsString()
  preferredUsername?: string;

  @IsOptional()
  @IsString()
  gender?: string;

  @IsOptional()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, {
    message: 'birthdate must be in YYYY-MM-DD format',
  })
  birthdate?: string;

  constructor({
    oidcId,
    email,
    familyName,
    givenName,
    preferredUsername,
    gender,
    birthdate,
  }: Partial<UserDto>) {
    this.oidcId = oidcId;
    this.email = email;
    this.familyName = familyName;
    this.givenName = givenName;
    this.preferredUsername = preferredUsername;
    this.gender = gender;
    this.birthdate = birthdate;
  }
}
