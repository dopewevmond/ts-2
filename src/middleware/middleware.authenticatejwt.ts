import { Request, Response, NextFunction } from 'express'
import * as jwt from 'jsonwebtoken'

const SECRET = process.env.SECRET as jwt.Secret
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET as jwt.Secret
[SECRET, REFRESH_SECRET].forEach((envVar) => {
  if (typeof envVar === 'undefined') {
    throw new Error('Not all environment variables are defined. Check .env.example file')
  }
})

const authenticateJWT = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader: string | undefined = req.headers.authorization

  if (typeof authHeader !== 'undefined') {
    const accessToken = authHeader.split(' ')[1]

    jwt.verify(accessToken, SECRET, (err, user) => {
      if (err instanceof Error) {
        return res.sendStatus(401)
      }
      res.locals.user = user
      next()
    })
  } else {
    res.sendStatus(401)
  }
}

export default authenticateJWT
