import Controller from './controller.interface'
import { Router, Request, Response, NextFunction, RequestHandler } from 'express'
import * as jwt from 'jsonwebtoken'
import TokenDetail from '../schema/tokenDetail'
import * as bcrypt from 'bcrypt'
import makeid from '../utils/utils.generateid'
import { signAccessToken, signRefreshToken, signPasswordResetToken } from '../utils/utils.signtoken'
import authenticateJWT from '../middleware/middleware.authenticatejwt'
import AppDataSource from '../datasource'
import User from '../entities/entity.user'

const userRepository = AppDataSource.getRepository(User)

const SECRET = process.env.SECRET as jwt.Secret
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET as jwt.Secret
[SECRET, REFRESH_SECRET].forEach((envVar) => {
  if (typeof envVar === 'undefined') {
    throw new Error('Not all environment variables are defined. Check .env.example file')
  }
})

let validPasswordResetTokens: TokenDetail[] = []
let validRefreshTokens: TokenDetail[] = []
const loggedOutAccessTokens: TokenDetail[] = []

class AuthController implements Controller {
  public path = '/auth'
  public router = Router()

  constructor () {
    this.ResetPasswordRequest = this.ResetPasswordRequest.bind(this)
    this.setupRoutes()
  }

  private setupRoutes (): void {
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.router.post(`${this.path}/login`, this.LoginHandler)
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.router.post(`${this.path}/register`, this.RegisterHandler)
    this.router.post(`${this.path}/reset-password-request`, this.ResetPasswordRequest)
    this.router.post(`${this.path}/reset-password`, this.ResetPasswordHandlerPost)
    this.router.post(`${this.path}/refresh-token`, this.RefreshTokenHandler)
    this.router.post(`${this.path}/logout`, authenticateJWT, this.LogoutHandler)
  }

  private async LoginHandler (req: Request, res: Response): Promise<void> {
    let errorMessage = 'email or password incorrect'

    const email: string = req.body.email
    const password: string = req.body.password

    if (email != null && password != null) {
      userRepository.findOneBy({ email })
        .then(async (user) => {
          if (user != null) {
            const passwordHash = await bcrypt.compare(password, user.password_hash)
            if (passwordHash) {
              // generate an id for the refresh token
              const tokenId = makeid(7)
              validRefreshTokens.push({ token_id: tokenId, email: user.email })

              const accessToken = signAccessToken(user.email, user.role, tokenId)
              const refreshToken = signRefreshToken(user.email, user.role, tokenId)
              res.json({ accessToken, refreshToken })
            } else {
              res.status(401).send({ message: errorMessage })
            }
          } else {
            res.status(401).json({ message: errorMessage })
          }
        })
        .catch((error) => {
          res.status(500).json({ message: error.message })
        })
    } else {
      errorMessage = 'please provide email and password in request body'
      res.status(400).json({ message: errorMessage })
    }
  }

  private async RegisterHandler (req: Request, res: Response): Promise<void> {
    let errorMessage = 'The email is already in use. Please select a new one'

    const email: string = req.body.email
    const password: string = req.body.password

    if (typeof email !== 'string' || typeof password !== 'string') {
      errorMessage = 'please provide email and password in request body'
    }

    const user = await userRepository.findOneBy({ email })

    // we want to create a new user only when its email does not exist
    if (user == null) {
      const salt = await bcrypt.genSalt(10)
      const hashedPassword = await bcrypt.hash(password, salt)

      const newUser = new User()
      newUser.email = email
      newUser.password_hash = hashedPassword
      newUser.role = 'member'
      const status = await userRepository.save(newUser)
      res.status(201).json({ message: 'user created successfully', id: status.id })
    } else {
      res.status(400).json({ message: errorMessage })
    }
  }

  private ResetPasswordHandlerPost (req: Request, res: Response): void {
    const token: string | undefined = req.body.resetToken
    const newPassword: string | undefined = req.body.newPassword

    if (typeof token === 'string' && typeof newPassword === 'string') {
      // eslint-disable-next-line @typescript-eslint/no-misused-promises
      jwt.verify(token, SECRET, async (err, user: jwt.JwtPayload) => {
        if (err instanceof Error) {
          return res.sendStatus(401)
        }

        // checking if its token id exists in the validResetTokens array
        // if it doesn't exist, it means a more recent password reset token has
        // been generated (or it has already been used), which makes it invalid
        const findTokenFromValidTokens: TokenDetail | undefined = validPasswordResetTokens.find(tokenObj => tokenObj.token_id === user.token_id)
        if (typeof findTokenFromValidTokens === 'undefined') {
          return res.sendStatus(401)
        }

        const userToChangePassword = await userRepository.findOneBy({ email: user.email })

        if (userToChangePassword != null) {
          const salt = await bcrypt.genSalt(10)
          userToChangePassword.password_hash = await bcrypt.hash(newPassword, salt)
          await userRepository.save(userToChangePassword)

          // after successfully resetting password we want to delete the token id from the validResetTokens
          validPasswordResetTokens = validPasswordResetTokens.filter(tokenObj => tokenObj.email !== userToChangePassword.email)
          res.status(200).json({ message: 'password changed successfully' })
        } else {
          res.status(404).json({ message: 'user does not exist' })
        }
      })
    } else {
      res.status(400).json({ message: 'Bad request' })
    }
  }

  private ResetPasswordRequest (req: Request, res: Response): void {
    const email = req.body.email

    if (email != null) {
      userRepository.findOneBy({ email })
        .then((user) => {
          if (user != null) {
            res.json({ passwordResetToken: this.getPasswordResetToken(email) })
          } else {
            res.status(400).json({ message: 'this email does not exist. please check the email and try again' })
          }
        })
        .catch((error) => {
          res.status(500).json({ message: error.message })
        })
    } else {
      res.status(400).json({ message: 'this email does not exist' })
    }
  }

  private getPasswordResetToken (email: string): string | undefined {
    // to invalidate any previously generated password reset tokens we keep track of the most...
    // ...recent token by generating a random token_id
    const tokenId = makeid(7)
    const previousTokenObj = validPasswordResetTokens.find(tokenObj => tokenObj.email === email)
    if (previousTokenObj != null) {
      // a reset token has previously been generated for that email so the...
      // ...token id is updated to this current token being created, thereby invalidating...
      // ...previously generated tokens
      previousTokenObj.token_id = tokenId
    } else {
      const currentTokenObj: TokenDetail = { token_id: tokenId, email }
      validPasswordResetTokens.push(currentTokenObj)
    }
    return signPasswordResetToken(email, tokenId)
  }

  private RefreshTokenHandler (req: Request, res: Response): void {
    const refreshToken: string | undefined = req.body.refreshToken

    if (typeof refreshToken === 'string') {
      jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
        if (err instanceof Error) {
          return res.sendStatus(401)
        }

        if (typeof user !== 'undefined') {
          const u: any = user

          // we want to invalidate an access token if it has already been used so...
          // ...we check if it exists in the list of valid refresh tokens
          const findTokenFromValidTokens: TokenDetail | undefined = validRefreshTokens.find(tokenObj => tokenObj.token_id === u.token_id)
          if (typeof findTokenFromValidTokens === 'undefined') {
            return res.sendStatus(401)
          }

          const newTokenId = makeid(7)
          const accessToken = signAccessToken(u.email, u.role, newTokenId)
          const refreshToken = signRefreshToken(u.email, u.role, newTokenId)

          // after signing a new refresh token let's invalidate the previous one by removing...
          // ...from the list of valid refresh tokens
          validRefreshTokens = validRefreshTokens.filter(tokenObj => tokenObj.token_id !== u.token_id)

          res.json({ accessToken, refreshToken })
        }
      })
    } else {
      res.sendStatus(401)
    }
  }

  private LogoutHandler (req: Request, res: Response): void {
    const userEmail: string = res.locals.user.email
    const tokenId: string = res.locals.user.token_id
    loggedOutAccessTokens.push({ email: userEmail, token_id: tokenId })

    res.json({ message: 'logged out successfully' })
  }
}

function getCheckBlacklistMiddleware (): RequestHandler {
  // passing in blacklistedAccessTokens by reference so that checkBlacklist (which will be exported from this file)...
  // ...can access it by virtue of a closure
  const blacklistedAccessTokens = loggedOutAccessTokens
  function checkBlacklist (req: Request, res: Response, next: NextFunction): void {
    const user = res.locals.user
    const findUserInBlacklist = blacklistedAccessTokens.find(tokenObj => tokenObj.token_id === user.token_id)

    if (typeof findUserInBlacklist !== 'undefined') {
      res.sendStatus(401)
    } else {
      next()
    }
  }
  return checkBlacklist
}

export { AuthController, getCheckBlacklistMiddleware }
