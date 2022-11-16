import * as express from 'express'
import Controller from './controllers/controller.interface'
import * as bodyParser from 'body-parser'
import * as dotenv from 'dotenv'
import logRequestDetails from './middleware/middleware.logrequest'

dotenv.config()

class App {
  public app: express.Application

  constructor (controllers: Controller[]) {
    this.app = express()
    this.setupApplication()
    controllers.forEach(controller => {
      this.app.use('/', controller.router)
    })
  }

  private setupApplication (): void {
    this.app.use(bodyParser.urlencoded({ extended: true }))
    this.app.use(bodyParser.json()) // get json data from request into req.body
    this.app.use(logRequestDetails)
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
