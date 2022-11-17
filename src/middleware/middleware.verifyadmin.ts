import { Request, Response, NextFunction } from 'express'
import * as jwt from 'jsonwebtoken'

const SECRET = process.env.SECRET as jwt.Secret
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET as jwt.Secret
[SECRET, REFRESH_SECRET].forEach((envVar) => {
  if (typeof envVar === 'undefined') {
    throw new Error('Not all environment variables are defined. Check .env.example file')
  }
})

const verifyAdmin = (req: Request, res: Response, next: NextFunction): void => {
  // this middleware will be mounted after authenticateJWT so the...
  // ...user object will exist on res.locals
  if (res.locals.user.role === 'admin') {
    next()
  } else {
    res.sendStatus(401)
  }
}

export default verifyAdmin
