import * as jwt from 'jsonwebtoken'

const SECRET = process.env.SECRET as jwt.Secret
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET as jwt.Secret
[SECRET, REFRESH_SECRET].forEach((envVar) => {
  if (typeof envVar === 'undefined') {
    throw new Error('Not all environment variables are defined. Check .env.example file')
  }
})

const ACCESS_TOKEN_EXPIRY_TIME = 600
const REFRESH_TOKEN_EXPIRY_TIME = '1d'

const signAccessToken = (email: string, role: string, tokenId: string): string => {
  return jwt.sign({ email, role, token_id: tokenId }, SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY_TIME })
}

const signRefreshToken = (email: string, role: string, tokenId: string): string => {
  return jwt.sign({ email, role, token_id: tokenId }, REFRESH_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY_TIME })
}

const signPasswordResetToken = (email: string, tokenId: string): string => {
  return jwt.sign({ email, token_id: tokenId }, SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY_TIME })
}

export { signAccessToken, signRefreshToken, signPasswordResetToken }
