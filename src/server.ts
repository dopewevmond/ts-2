import App from './app'
import MainController from './controllers/controller.main'

const app = new App([
  new MainController()
])

app.listen()
