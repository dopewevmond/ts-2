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
    this.setupRoutes()
  }

  private setupRoutes (): void {
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.router.post(`${this.path}/login`, this.LoginHandler)
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.router.post(`${this.path}/register`, this.RegisterHandler)
  }

  private async LoginHandler (req: Request, res: Response): Promise<void> {
    let errorMessage = 'username or password incorrect'

    const email: string = req.body.email
    const password: string = req.body.password

    if (typeof email !== 'string' || typeof password !== 'string') {
      errorMessage = 'please provide email and password in request body'
    }

    const user: User | undefined = users.find(u => u.email === email)

    if (typeof user !== 'undefined') {
      const passwordHash = await bcrypt.compare(password, user.password_hash)
      if (passwordHash) {
        const accessToken = jwt.sign({ username: user.email, role: user.role }, SECRET)
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
}

export default AuthController
