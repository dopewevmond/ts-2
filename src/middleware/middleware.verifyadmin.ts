import { Request, Response, NextFunction } from 'express'

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
