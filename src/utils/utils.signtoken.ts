import * as jwt from 'jsonwebtoken'

let SECRET: jwt.Secret
if (typeof process.env.SECRET === 'string') {
  SECRET = process.env.SECRET
} else {
  SECRET = 'N0T@reallyG00ds3cr3t'
}

let REFRESH_SECRET: jwt.Secret
if (typeof process.env.REFRESH_TOKEN_SECRET === 'string') {
  REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET
} else {
  REFRESH_SECRET = 'N0T@reallyG00dR3fr3shs3cr3t'
}

const ACCESS_TOKEN_EXPIRY_TIME = 60
const REFRESH_TOKEN_EXPIRY_TIME = '1d'

const signAccessToken = (email: string, role: string): string => {
  return jwt.sign({ email, role }, SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY_TIME })
}

const signRefreshToken = (email: string, role: string, tokenId: string): string => {
  return jwt.sign({ email, role, token_id: tokenId }, REFRESH_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY_TIME })
}

const signPasswordResetToken = (email: string, tokenId: string): string => {
  return jwt.sign({ email, token_id: tokenId }, SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY_TIME })
}

export { signAccessToken, signRefreshToken, signPasswordResetToken }
