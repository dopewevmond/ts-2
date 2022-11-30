/* eslint-disable @typescript-eslint/no-misused-promises */
import Controller from './controller.interface'
import { Router, Request, Response, NextFunction } from 'express'
import * as jwt from 'jsonwebtoken'
import * as bcrypt from 'bcrypt'
import makeid from '../utils/utils.generateid'
import { signAccessToken, signRefreshToken, signPasswordResetToken } from '../utils/utils.signtoken'
import AppDataSource from '../datasource'
import User from '../entities/entity.user'
import AppError from '../exceptions/exception.apperror'
import * as redis from 'redis'
import IRedisPrefix from '../schema/redisprefix'

const userRepository = AppDataSource.getRepository(User)

const SECRET = process.env.SECRET as jwt.Secret
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET as jwt.Secret

[SECRET, REFRESH_SECRET].forEach((envVar) => {
  if (typeof envVar === 'undefined') {
    throw new Error('Not all environment variables are defined. Check .env.example file')
  }
})

// connecting to redis
let redisClient: redis.RedisClientType
;(async () => {
  redisClient = redis.createClient()
  redisClient.on('error', (error) => console.error(error))

  await redisClient.connect()
})()
  .then(() => console.log('auth connected to redis...'))
  .catch((err) => { console.log(err) })


class AuthController implements Controller {
  public path = '/auth'
  public router = Router()

  constructor () {
    this.ResetPasswordRequest = this.ResetPasswordRequest.bind(this)
    this.setupRoutes()
  }

  private setupRoutes (): void {
    this.router.post(`${this.path}/login`, this.LoginHandler)
    this.router.post(`${this.path}/register`, this.RegisterHandler)
    this.router.post(`${this.path}/reset-password-request`, this.ResetPasswordRequest)
    this.router.post(`${this.path}/reset-password`, this.ResetPasswordHandlerPost)
    this.router.post(`${this.path}/refresh-token`, this.RefreshTokenHandler)
    this.router.post(`${this.path}/logout`, this.LogoutHandler)
  }

  private async LoginHandler (req: Request, res: Response, next: NextFunction): Promise<void> {
    const email: string = req.body.email
    const password: string = req.body.password

    try {
      if (email != null && password != null) {
        const user = await userRepository.findOneBy({ email })
        if (user != null) {
          const passwordMatch = await bcrypt.compare(password, user.password_hash)
          if (passwordMatch) {
            const tokenId = makeid(128)
            const redisPrefix: IRedisPrefix = 'refreshToken-'
            await redisClient.set(redisPrefix + tokenId, 'exists')
            const accessToken = signAccessToken(user.email, user.role, tokenId)
            const refreshToken = signRefreshToken(user.email, user.role, tokenId)
            res.json({ accessToken, refreshToken })
          } else {
            next(new AppError(401, 'email or password incorrect'))
          }
        } else {
          next(new AppError(401, 'email or password incorrect'))
        }
      } else {
        next(new AppError(400, 'email or password missing from request'))
      }
    } catch (error) {
      next(new AppError(401, error.message))
    }
  }

  private async RegisterHandler (req: Request, res: Response, next: NextFunction): Promise<void> {
    const email: string = req.body.email
    const password: string = req.body.password

    try {
      if (email != null && password != null) {
        const user = await userRepository.findOneBy({ email })
        // we want to create a new user only when its email does not exist
        if (user == null) {
          const salt = await bcrypt.genSalt(10)
          const hashedPassword = await bcrypt.hash(password, salt)
          const newUser = new User()
          newUser.email = email
          newUser.password_hash = hashedPassword
          newUser.role = 'member'
          const createdUser = await userRepository.save(newUser)
          res.status(201).json({ message: 'user created successfully', id: createdUser.id })
        } else {
          next(new AppError(401, 'user with same email already exists. please choose another'))
        }
      } else {
        next(new AppError(400, 'email or password missing from request'))
      }
    } catch (error) {
      next(new AppError(500, error.message))
    }
  }

  private async ResetPasswordHandlerPost (req: Request, res: Response): Promise<void> {
    const token: string = req.body.resetToken
    const newPassword: string = req.body.newPassword

    if (token != null && newPassword != null) {
      try {
        const user = jwt.verify(token, SECRET) as jwt.JwtPayload
        // checking if its token id exists in the validResetTokens array
        // if it doesn't exist, it means a more recent password reset token has
        // been generated (or it has already been used), which makes it invalid
        const redisPrefix: IRedisPrefix = 'resetToken-'
        const tokenObj = await redisClient.get(redisPrefix + user.email)

        if (tokenObj != null) {
          const userToChangePassword = await userRepository.findOneBy({ email: user.email })
          if (userToChangePassword != null) {
            const salt = await bcrypt.genSalt(10)
            userToChangePassword.password_hash = await bcrypt.hash(newPassword, salt)
            await userRepository.save(userToChangePassword)
            await redisClient.del('resetToken-' + user.email)
            res.status(200).json({ message: 'password changed successfully' })
          } else {
            res.status(404).json({ message: 'the user was not found' })
          }
        } else {
          res.status(401).json({ message: 'the password reset token is invalid' })
        }
      } catch (error) {
        res.status(401).json({ message: error.message })
      }
    } else {
      res.status(400).json({ message: 'password reset token or new password missing from request' })
    }
  }

  private async ResetPasswordRequest (req: Request, res: Response, next: NextFunction): Promise<void> {
    const email = req.body.email
    try {    
      if (email != null) {
        const user = await userRepository.findOneBy({ email })
        if (user != null) {
          res.json({ passwordResetToken: this.getPasswordResetToken(email) })
        } else {
          res.status(404).json({ message: 'this email does not exist. please check the email and try again' })
        }
      } else {
        res.status(400).json({ message: 'email missing from request' })
      }
    } catch (error) {
      next(new AppError(500, 'an error occurred'))
    }
  }

  private async getPasswordResetToken (email: string): Promise<string|undefined> {
    // to invalidate any previously generated password reset tokens we keep track of the most...
    // ...recent token by generating a random token_id
    const tokenId = makeid(128)
    const redisPrefix: IRedisPrefix = 'resetToken-'
    const prevResetTokenObj = await redisClient.get(redisPrefix + email)
    if (prevResetTokenObj != null) {
      const deserializedTokenObj = JSON.parse(prevResetTokenObj)
      deserializedTokenObj.token_id = tokenId
      await redisClient.set(redisPrefix + email, JSON.stringify(deserializedTokenObj))
    } else {
      const newPasswordRefreshTokenObj = { token_id: tokenId, email }
      await redisClient.set(redisPrefix + email, JSON.stringify(newPasswordRefreshTokenObj))
    }
    return signPasswordResetToken(email, tokenId)
  }

  private async RefreshTokenHandler (req: Request, res: Response, next: NextFunction): Promise<void> {
    const refreshToken: string | undefined = req.body.refreshToken

    if (refreshToken != null) {
      try {
        const decoded = jwt.verify(refreshToken, REFRESH_SECRET)
        const u: any = decoded
        const refreshTokenId: string = u.token_id
        const redisPrefix: IRedisPrefix = 'refreshToken-'
        const isRefreshTokenValid = redisClient.get(redisPrefix + refreshTokenId)

        if (isRefreshTokenValid != null) {
          const newTokenId = makeid(128)
          const accessToken = signAccessToken(u.email, u.role, newTokenId)
          const refreshToken = signRefreshToken(u.email, u.role, newTokenId)

          // we've used the refresh token to generate new access and refresh tokens to we should invalidate the previous one
          await redisClient.del(redisPrefix + refreshTokenId)
          await redisClient.set(redisPrefix + newTokenId, 'exists')
          res.json({ accessToken, refreshToken })
        } else {
          next(new AppError(401, 'invalid refresh token'))
        }
      } catch (error) {
        next(new AppError(401, error.message))
      }
    } else {
      next(new AppError(401, 'refresh token missing from request'))
    }
  }

  private async LogoutHandler (req: Request, res: Response): Promise<void> {
    const tokenId: string = res.locals.user.token_id
    const redisPrefix: IRedisPrefix = 'loggedOutAccessToken-'
    await redisClient.set(redisPrefix + tokenId, 'exists')

    res.json({ message: 'logged out successfully' })
  }
}

export default AuthController
