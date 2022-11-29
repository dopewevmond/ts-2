import * as express from 'express'
import Controller from './controllers/controller.interface'
import * as bodyParser from 'body-parser'
import * as dotenv from 'dotenv'
import * as Sentry from '@sentry/node'
import '@sentry/tracing'
import * as morgan from 'morgan'
import AppError from './exceptions/exception.apperror'

dotenv.config()

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
    this.app.use(bodyParser.json()) // get json data from request into req.body
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
