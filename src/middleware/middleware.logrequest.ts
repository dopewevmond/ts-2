import { Request, Response, NextFunction } from 'express'

/**
 * Logs the method, url and date/time of a request to the console
 * @param req Request object
 * @param res Response object
 * @param next Call next middleware
 */
const logRequestDetails = (req: Request, res: Response, next: NextFunction): void => {
  const dateTime = new Date()
  console.log(`${req.method} ${req.url} --- ${dateTime.toDateString()} --- ${dateTime.toTimeString()}`)
  next()
}

export default logRequestDetails
