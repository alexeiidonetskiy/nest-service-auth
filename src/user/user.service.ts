import { ConflictException, Injectable } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { UserEntity } from './entity/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  constructor(
    @InjectEntityManager()
    private readonly em: EntityManager,
  ) {}

  public static validateCredentials(
    user: UserEntity,
    password: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, user.password);
  }

  async findOneByEmail(email: string): Promise<UserEntity> {
    const user = this.em.findOneBy(UserEntity, { email });
    return user || undefined;
  }

  async create(createUserDto: CreateUserDto): Promise<UserEntity> {
    const { email } = createUserDto;
    const user = await this.em.findOneBy(UserEntity, { email });

    if (user) {
      throw new ConflictException(`The email: ${email} is already taken`);
    }

    const newUser = this.em.create(UserEntity, { ...createUserDto });
    const savedUser = await this.em.save(newUser);
    return savedUser;
  }

  async update(email: string, updatePayload: Partial<UserEntity>) {
    const user = await this.findOneByEmail(email);
    const updatedUser = this.em.merge(UserEntity, user, updatePayload);

    return this.em.save(updatedUser);
  }
}
