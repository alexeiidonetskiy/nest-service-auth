import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { ConfigModule } from '@nestjs/config';
import { UserEntity } from './user/entity/user.entity';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      port: 54322,
      username: 'postgres',
      password: 'postgres',
      database: 'auth',
      entities: [UserEntity],
      synchronize: true,
    }),
    ConfigModule.forRoot(),
    AuthModule,
    UserModule,
  ],
})
export class AppModule {}
