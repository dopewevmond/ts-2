import App from './app'
import MainController from './controllers/controller.main'
import LoginController from './controllers/controller.login'

const app = new App([
  new MainController(),
  new LoginController()
])

app.listen()
