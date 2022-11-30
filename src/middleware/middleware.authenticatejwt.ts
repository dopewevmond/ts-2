import { Request, Response, NextFunction } from 'express'
import * as jwt from 'jsonwebtoken'

const SECRET = process.env.SECRET as jwt.Secret

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
