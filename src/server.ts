import App from './app'
import MainController from './controllers/controller.main'
import { AuthController } from './controllers/controller.auth'

const app = new App([
  new MainController(),
  new AuthController()
])

app.listen()
