import Controller from './controller.interface'
import { Router, Request, Response, NextFunction, RequestHandler } from 'express'
import * as jwt from 'jsonwebtoken'
import User from '../schema/user'
import TokenDetail from '../schema/tokenDetail'
import * as bcrypt from 'bcrypt'
import makeid from '../utils/utils.generateid'
import { signAccessToken, signRefreshToken, signPasswordResetToken } from '../utils/utils.signtoken'
import authenticateJWT from '../middleware/middleware.authenticatejwt'

// secret to be used to sign the jwt
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
  REFRESH_SECRET = 'N0T@reallyG00dR3fr3shs3cr3t'
}

const users: User[] = []
let validPasswordResetTokens: TokenDetail[] = []
let validRefreshTokens: TokenDetail[] = []
const loggedOutAccessTokens: TokenDetail[] = []

class AuthController implements Controller {
  public path = '/auth'
  public router = Router()

  constructor () {
    this.ResetPasswordHandlerGet = this.ResetPasswordHandlerGet.bind(this)
    this.setupRoutes()
  }

  private setupRoutes (): void {
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.router.post(`${this.path}/login`, this.LoginHandler)
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.router.post(`${this.path}/register`, this.RegisterHandler)
    this.router.get(`${this.path}/reset_password`, this.ResetPasswordHandlerGet)
    this.router.post(`${this.path}/reset_password`, this.ResetPasswordHandlerPost)
    this.router.post(`${this.path}/refresh-token`, this.RefreshTokenHandler)
    this.router.post(`${this.path}/logout`, authenticateJWT, this.LogoutHandler)
  }

  private async LoginHandler (req: Request, res: Response): Promise<void> {
    let errorMessage = 'email or password incorrect'

    const email: string = req.body.email
    const password: string = req.body.password

    if (typeof email !== 'string' || typeof password !== 'string') {
      errorMessage = 'please provide email and password in request body'
    }

    const user: User | undefined = users.find(u => u.email === email)

    if (typeof user !== 'undefined') {
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
  }

  private async RegisterHandler (req: Request, res: Response): Promise<void> {
    let errorMessage = 'The email is already in use. Please select a new one'

    const email: string = req.body.email
    const password: string = req.body.password

    if (typeof email !== 'string' || typeof password !== 'string') {
      errorMessage = 'please provide email and password in request body'
    }

    const user: User | undefined = users.find(u => u.email === email)

    if (typeof user === 'undefined') {
      const salt = await bcrypt.genSalt(10)
      const hashedPassword = await bcrypt.hash(password, salt)
      const newUser: User = {
        email,
        password_hash: hashedPassword,
        role: 'member'
      }
      users.push(newUser)
      res.status(201).json({ message: 'user created successfully' })
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

        const userToChangePassword: User | undefined = users.find(u => u.email === user.email)

        if (typeof userToChangePassword !== 'undefined') {
          const salt = await bcrypt.genSalt(10)
          userToChangePassword.password_hash = await bcrypt.hash(newPassword, salt)

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

  private ResetPasswordHandlerGet (req: Request, res: Response): void {
    const email: string | undefined = req.body.email
    const user: User | undefined = users.find(u => u.email === email)

    if (typeof email !== 'undefined' && typeof user !== 'undefined') {
      res.json({ passwordResetToken: this.getPasswordResetToken(email) })
    } else {
      res.json({ message: 'a link containing reset instructions has been sent to your email' })
    }
  }

  private getPasswordResetToken (email: string): string | undefined {
    const user: User | undefined = users.find(u => u.email === email)

    if (typeof user !== 'undefined') {
      // to invalidate any previously generated password reset tokens we keep track of the most...
      // ...recent token by generating a random token_id
      const tokenId = makeid(7)
      const previousTokenObj = validPasswordResetTokens.find(tokenObj => tokenObj.email === user.email)
      if (typeof previousTokenObj !== 'undefined') {
        // a reset token has previously been generated for that email so the...
        // ...token id is updated to this current token being created, thereby invalidating...
        // ...previously generated tokens
        previousTokenObj.token_id = tokenId
      } else {
        const currentTokenObj: TokenDetail = { token_id: tokenId, email: user.email }
        validPasswordResetTokens.push(currentTokenObj)
      }
      return signPasswordResetToken(user.email, tokenId)
    } else {
      return undefined
    }
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
