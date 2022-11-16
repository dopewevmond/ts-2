import { Router, Request, Response } from 'express'
import Controller from './controller.interface'
import authenticateJWT from '../middleware/middleware.authenticatejwt'

const books = [
  {
    author: 'Chinua Achebe',
    country: 'Nigeria',
    language: 'English',
    pages: 209,
    title: 'Things Fall Apart',
    year: 1958
  },
  {
    author: 'Hans Christian Andersen',
    country: 'Denmark',
    language: 'Danish',
    pages: 784,
    title: 'Fairy tales',
    year: 1836
  },
  {
    author: 'Dante Alighieri',
    country: 'Italy',
    language: 'Italian',
    pages: 928,
    title: 'The Divine Comedy',
    year: 1315
  }
]

class MainController implements Controller {
  public path = '/'
  public router = Router()

  constructor () {
    this.setupRoutes()
  }

  private setupRoutes (): void {
    this.router.get(
      this.path,
      authenticateJWT,
      this.Homehandler
    )
  }

  private Homehandler (req: Request, res: Response): void {
    res.json({ books })
  }
}

export default MainController
