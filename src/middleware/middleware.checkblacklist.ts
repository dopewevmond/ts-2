import * as redis from 'redis'
import { Request, Response, NextFunction } from 'express'
import AppError from '../exceptions/exception.apperror'
import IRedisPrefix from '../schema/redisprefix'

let redisClient: redis.RedisClientType

;(async () => {
  redisClient = redis.createClient()
  redisClient.on('error', (error) => console.error(error))

  await redisClient.connect()
})()
  .then(() => console.log('middleware connected to redis...'))
  .catch((err) => { console.log(err) })

const checkBlacklist = (req: Request, res: Response, next: NextFunction): void => {
  // should always be called after authenticatejwt middleware
  // by then it will have res.locals.user set already
  const user = res.locals.user
  const tokenId = user.token_id as string
  const redisPrefix: IRedisPrefix = 'loggedOutAccessToken-'
  redisClient.get(redisPrefix + tokenId)
    .then((val) => {
      if (val == null) {
        next()
      } else {
        next(new AppError(401, 'unauthorized'))
      }
    })
    .catch((_err) => {
      next(new AppError(500, 'error reading from redis server'))
    })
}

export default checkBlacklist
