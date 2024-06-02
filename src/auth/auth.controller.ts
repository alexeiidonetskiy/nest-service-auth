import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../user/dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { UserEntity } from '../user/entity/user.entity';
import { GetUser } from './decorators/get-user.decorator';
import { JwtPayload } from './interface/jwt-payload.interface';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Controller({
  path: '/auth',
})
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/login')
  login(@Body() loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto);
  }

  @Post('/register')
  register(@Body() createUserDto: CreateUserDto) {
    return this.authService.register(createUserDto);
  }

  @Post('/logout')
  logout(@GetUser() user: UserEntity) {
    return this.authService.logout(user.email);
  }

  @Post('/refresh-token')
  refreshToken(
    @GetUser() user: JwtPayload,
    @Body() refreshTokenDto: RefreshTokenDto,
  ) {
    return this.authService.refreshTokens(user, refreshTokenDto);
  }
}
