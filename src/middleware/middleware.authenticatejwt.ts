import { Request, Response, NextFunction } from 'express'
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
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  REFRESH_SECRET = 'N0T@reallyG00dR3fr3shs3cr3t'
}

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
