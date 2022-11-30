import * as jwt from 'jsonwebtoken'

const SECRET = process.env.SECRET as jwt.Secret
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET as jwt.Secret
const ACCESS_TOKEN_EXPIRY_TIME = process.env.ACCESS_TOKEN_EXPIRY_TIME as string
const REFRESH_TOKEN_EXPIRY_TIME = process.env.REFRESH_TOKEN_EXPIRY_TIME as string

const signAccessToken = (email: string, role: string, tokenId: string): string => {
  return jwt.sign({ email, role, token_id: tokenId }, SECRET, { expiresIn: parseInt(ACCESS_TOKEN_EXPIRY_TIME) })
}

const signRefreshToken = (email: string, role: string, tokenId: string): string => {
  return jwt.sign({ email, role, token_id: tokenId }, REFRESH_SECRET, { expiresIn: parseInt(REFRESH_TOKEN_EXPIRY_TIME) })
}

const signPasswordResetToken = (email: string, tokenId: string): string => {
  return jwt.sign({ email, token_id: tokenId }, SECRET, { expiresIn: parseInt(REFRESH_TOKEN_EXPIRY_TIME) })
}

export { signAccessToken, signRefreshToken, signPasswordResetToken }
