import { Request, Response, NextFunction } from 'express'
import * as jwt from 'jsonwebtoken'

let SECRET: jwt.Secret
if (typeof process.env.SECRET === 'string') {
  SECRET = process.env.SECRET
} else {
  SECRET = 'N0T@reallyG00ds3cr3t'
}

const authenticateJWT = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader: string | undefined = req.headers.authorization

  if (typeof authHeader !== 'undefined') {
    const token = authHeader.split(' ')[1]

    jwt.verify(token, SECRET, (err, user) => {
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
