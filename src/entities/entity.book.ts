import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm'

@Entity()
class Book {
  @PrimaryGeneratedColumn()
    id: number

  @Column('varchar', { length: 100 })
    author: string

  @Column('varchar', { length: 100 })
    country: string

  @Column('varchar', { length: 100 })
    language: string

  @Column('varchar', { length: 100 })
    title: string

  @Column()
    pages: number

  @Column()
    year: number
}

export default Book
