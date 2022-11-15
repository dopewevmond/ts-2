import Controller from './controller.interface'
import { Router, Request, Response } from 'express'
import * as jwt from 'jsonwebtoken'
import User from '../schema/user'

// secret to be used to sign the jwt
let SECRET: jwt.Secret
if (typeof process.env.SECRET === 'string') {
  SECRET = process.env.SECRET
} else {
  SECRET = 'N0T@reallyG00ds3cr3t'
}

const users: User[] = [
  {
    username: 'john',
    password: 'password123admin',
    role: 'admin'
  }, {
    username: 'anna',
    password: 'password123member',
    role: 'member'
  }
]

class LoginController implements Controller {
  public path = '/login'
  public router = Router()

  constructor () {
    this.setupRoutes()
  }

  private setupRoutes (): void {
    this.router.post(this.path, this.LoginHandler)
  }

  private LoginHandler (req: Request, res: Response): void {
    let errorMessage = 'username or password incorrect'

    const username: string = req.body.username
    const password: string = req.body.password

    if (typeof username !== 'string' || typeof password !== 'string') {
      errorMessage = 'please provide username and password in request body'
    }

    const user: User | undefined = users.find(u => u.username === username && u.password === password)

    if (typeof user !== 'undefined') {
      const accessToken = jwt.sign({ username: user.username, role: user.role }, SECRET)

      res.json({ token: accessToken })
    }

    res.send(errorMessage)
  }
}

export default LoginController
