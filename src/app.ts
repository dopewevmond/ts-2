import * as express from 'express'
import Controller from './controllers/controller.interface'
import * as bodyParser from 'body-parser'
import * as dotenv from 'dotenv'
import * as Sentry from '@sentry/node'
import '@sentry/tracing'
import * as morgan from 'morgan'
import AppError from './exceptions/exception.apperror'

dotenv.config()

const PORT = process.env.PORT as string
const SECRET = process.env.SECRET as string
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string
const DB_HOST = process.env.DB_HOST as string
const DB_PORT = process.env.DB_PORT as string
const DB_USERNAME = process.env.DB_USERNAME as string
const DB_PASSWORD = process.env.DB_PASSWORD as string
const DB_NAME = process.env.DB_NAME as string
const REDIS_HOST = process.env.REDIS_HOST as string
const REDIS_PORT = process.env.REDIS_PORT as string
const ACCESS_TOKEN_EXPIRY_TIME = process.env.ACCESS_TOKEN_EXPIRY_TIME as string
const RESET_TOKEN_EXPIRY_TIME = process.env.PASSWORD_RESET_TOKEN_EXPIRY_TIME as string
const REFRESH_TOKEN_EXPIRY_TIME = process.env.REFRESH_TOKEN_EXPIRY_TIME as string

[
  PORT,SECRET, REFRESH_TOKEN_SECRET, DB_HOST, DB_PORT,
  DB_USERNAME, DB_PASSWORD, DB_NAME, REDIS_HOST, REDIS_PORT,
  ACCESS_TOKEN_EXPIRY_TIME, REFRESH_TOKEN_EXPIRY_TIME, RESET_TOKEN_EXPIRY_TIME
].forEach((envVar) => {
  if (typeof envVar === 'undefined' || envVar === '') {
    throw new Error(`${envVar} environment variable not defined. check .env file for details`)
  }
})

class App {
  public app: express.Application

  constructor (controllers: Controller[]) {
    this.app = express()
    Sentry.init({ dsn: 'https://b76619ae6aa641258556f6cc028ef7a4@o4504203419648000.ingest.sentry.io/4504203423711232' })
    this.app.use(Sentry.Handlers.requestHandler())

    this.setupApplication()
    controllers.forEach(controller => {
      this.app.use('/', controller.router)
    })

    this.app.use(Sentry.Handlers.errorHandler())
    this.app.use(this.ErrorHandlerMiddleware)
  }

  private setupApplication (): void {
    this.app.use(bodyParser.urlencoded({ extended: true }))
    this.app.use(bodyParser.json())
    this.app.use(morgan('dev'))
  }

  private ErrorHandlerMiddleware (error: AppError, req: express.Request, res: express.Response, next: express.NextFunction): void {
    res.status(error.statusCode).json({ message: error.message })
  }

  public listen (): void {
    let port: number
    if (typeof process.env.PORT === 'string') {
      port = parseInt(process.env.PORT)
    } else {
      port = 3000
    }
    this.app.listen(port, () => {
      console.log(`Listening on port: ${port}`)
    })
  }
}

export default App
