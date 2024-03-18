export interface JwtPayload {
  oidcId: string;
  idToken: string;
  state: string;
}
