import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';
import { Expose } from 'class-transformer';

export class CreateUserDto {
  @IsNotEmpty()
  @Expose()
  readonly name: string;

  @IsNotEmpty()
  @IsEmail()
  @Expose()
  readonly email: string;

  @IsNotEmpty()
  @MinLength(8)
  readonly password: string;
}
