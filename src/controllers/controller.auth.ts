import Controller from './controller.interface'
import { Router, Request, Response } from 'express'
import * as jwt from 'jsonwebtoken'
import User from '../schema/user'
import * as bcrypt from 'bcrypt'

// secret to be used to sign the jwt
let SECRET: jwt.Secret
if (typeof process.env.SECRET === 'string') {
  SECRET = process.env.SECRET
} else {
  SECRET = 'N0T@reallyG00ds3cr3t'
}

const users: User[] = []

class AuthController implements Controller {
  public path = '/auth'
  public router = Router()

  constructor () {
    this.resetPasswordHandlerGet = this.resetPasswordHandlerGet.bind(this)

    this.setupRoutes()
  }

  private setupRoutes (): void {
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.router.post(`${this.path}/login`, this.LoginHandler)
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.router.post(`${this.path}/register`, this.RegisterHandler)
    this.router.get(`${this.path}/reset_password`, this.resetPasswordHandlerGet)
    this.router.post(`${this.path}/reset_password`, this.ResetPasswordHandlerPost)
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
        const accessToken = jwt.sign({ email: user.email, role: user.role }, SECRET)
        res.json({ token: accessToken })
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

        const userToChangePassword: User | undefined = users.find(u => u.email === user.email)

        if (typeof userToChangePassword !== 'undefined') {
          const salt = await bcrypt.genSalt(10)
          userToChangePassword.password_hash = await bcrypt.hash(newPassword, salt)
          res.status(200).json({ message: 'password changed successfully' })
        } else {
          res.status(404).json({ message: 'user does not exist' })
        }
      })
    } else {
      res.status(400).json({ message: 'Bad request' })
    }
  }

  private resetPasswordHandlerGet (req: Request, res: Response): void {
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
      return jwt.sign({ email: user.email }, SECRET, { expiresIn: '10m' })
    } else {
      return undefined
    }
  }
}

export default AuthController
