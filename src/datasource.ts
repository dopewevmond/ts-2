import 'reflect-metadata'
import { DataSource } from 'typeorm'
import Book from './entities/entity.book'
import User from './entities/entity.user'

const DB_HOST = process.env.DB_HOST as string
const DB_PORT = process.env.DB_PORT as string
const DB_USERNAME = process.env.DB_USERNAME as string
const DB_PASSWORD = process.env.DB_PASSWORD as string
const DB_NAME = process.env.DB_NAME as string

const AppDataSource = new DataSource({
  type: 'postgres',
  host: DB_HOST,
  port: parseInt(DB_PORT),
  username: DB_USERNAME,
  password: DB_PASSWORD,
  database: DB_NAME,
  entities: [Book, User],
  synchronize: false
})

AppDataSource.initialize()
  .then(() => {
    console.log('connected to database...')
  })
  .catch((error) => {
    console.error(error)
  })

export default AppDataSource
