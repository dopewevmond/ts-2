import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm'

@Entity()
class User {
  @PrimaryGeneratedColumn()
    id: number

  @Column('varchar', { length: 255 })
    email: string

  @Column('varchar', { length: 500 })
    password_hash: string

  @Column('varchar', { length: 50 })
    role: string
}

export default User
