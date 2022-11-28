import { Router, Request, Response } from 'express'
import Controller from './controller.interface'
import authenticateJWT from '../middleware/middleware.authenticatejwt'
import checkBlacklist from '../middleware/middleware.checkblacklist'
import verifyAdmin from '../middleware/middleware.verifyadmin'
import AppDataSource from '../datasource'
import Book from '../entities/entity.book'

const booksRepository = AppDataSource.getRepository(Book)

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
    booksRepository.find()
      .then((books) => {
        res.json({ books })
      })
      .catch(({ message }) => {
        res.status(500).json({ message })
      })
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
      const book = new Book()
      book.author = author
      book.country = country
      book.language = language
      book.pages = parseInt(pages)
      book.title = title
      book.year = parseInt(year)
      booksRepository.save(book)
        .then((savedBook) => {
          res.status(201).json({ message: 'book created successfully', ...savedBook })
        })
        .catch(({ message }) => {
          res.status(500).json({ message })
        })
    } else {
      res.sendStatus(400)
    }
  }
}

export default MainController
