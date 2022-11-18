import { Router, Request, Response } from 'express'
import Controller from './controller.interface'
import authenticateJWT from '../middleware/middleware.authenticatejwt'
import checkBlacklist from '../middleware/middleware.checkblacklist'
import verifyAdmin from '../middleware/middleware.verifyadmin'
import Book from '../schema/book'

const books: Book[] = [
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
    this.router.get(this.path, authenticateJWT, checkBlacklist, this.Homehandler)
    this.router.post(this.path, authenticateJWT, checkBlacklist, verifyAdmin, this.AddBookHandler)
  }

  private Homehandler (req: Request, res: Response): void {
    res.json({ books })
  }

  private AddBookHandler (req: Request, res: Response): void {
    const author: string = req.body.author
    const country: string = req.body.country
    const language: string = req.body.language
    const pages: string = req.body.pages
    const title: string = req.body.title
    const year: string = req.body.year

    const badRequest = [author, country, language, pages, title, year].find(prop => typeof prop === 'undefined')
    if (typeof badRequest === 'undefined') {
      books.push({
        author,
        country,
        language,
        pages: parseInt(pages),
        title,
        year: parseInt(year)
      })
      res.status(201).json({ message: 'book uploaded' })
    } else {
      res.sendStatus(400)
    }
  }
}

export default MainController
