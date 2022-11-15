import Controller from './controller.interface'
import { Router, Request, Response } from 'express'

class MainController implements Controller {
  public path = '/'
  public router = Router()

  constructor () {
    this.setupRoutes()
  }

  private setupRoutes (): void {
    this.router.get('/', this.Homehandler)
  }

  private Homehandler (req: Request, res: Response): void {
    res.json(
      {
        status: 'success'
      }
    )
  }
}

export default MainController
