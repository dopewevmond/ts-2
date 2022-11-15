import * as express from 'express'
import Controller from './controllers/controller.interface'
import * as bodyParser from 'body-parser'
import * as path from 'path'
import * as dotenv from 'dotenv'

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
    this.app.use('/public', express.static(path.join(__dirname, '/../public'))) // serve static assets only on public route
    this.app.set('views', path.join(__dirname, '/../views')) // where to locate templates
    this.app.set('view engine', 'pug') // using pug view engine for templates
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
