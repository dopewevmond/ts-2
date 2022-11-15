import { Request, Response, NextFunction } from 'express'

const logRequestDetails = (req: Request, res: Response, next: NextFunction): void => {
  console.log(`${req.method} ${req.url} ${new Date().getDate()}`)
}

export default logRequestDetails
