export interface DecodedIdToken {
  aud: string;
  nonce: string;
  at_hash: string;
}

export interface TokensResponse {
  idToken: string;
  accessToken: string;
}

export interface OIDCConfiguration {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  end_session_endpoint: string;
}

export interface CallbackQuery {
  code: string;
  state: string;
}

export interface OidcProfile {
  sub: string;
  email?: string;
  family_name?: string;
  given_name?: string;
  preferred_username?: string;
  gender?: string;
  birthdate?: string;
}
