import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { CreateUserDto } from '../user/dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtPayload } from './interface/jwt-payload.interface';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { UserEntity } from '../user/entity/user.entity';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
    private readonly configService: ConfigService,
  ) {}

  private static async hashData(data: string) {
    return await bcrypt.hash(data, 10);
  }

  private static async compareHashed(data: string, source: string) {
    return await bcrypt.compare(data, source);
  }

  private logger = new Logger(AuthService.name);

  async login(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    const user = await this.userService.findOneByEmail(email);

    if (!user) {
      throw new BadRequestException('Wrong email or password');
    }

    const isValidPassword = UserService.validateCredentials(user, password);
    if (!isValidPassword) {
      throw new BadRequestException('Wrong email or password');
    }

    const tokens = await this.getTokens({
      sub: user.id,
      email: user.email,
    });

    await this.updateUserRefreshToken(user.email, tokens.refreshToken);
    return tokens;
  }

  async register(createUserDto: CreateUserDto) {
    const { email, password } = createUserDto;
    const user = await this.userService.findOneByEmail(email);

    if (user) {
      throw new BadRequestException('Email is already taken');
    }

    const hashedPassword = await AuthService.hashData(password);
    const newUser = await this.userService.create({
      ...createUserDto,
      password: hashedPassword,
    });

    const tokens = await this.getTokens({
      sub: newUser.id,
      email: newUser.email,
    });

    await this.updateUserRefreshToken(email, tokens.refreshToken);
    return tokens;
  }

  async logout(email: string) {
    await this.userService.update(email, {
      refreshToken: null,
    });
  }

  async refreshTokens(user: JwtPayload, refreshTokenDto: RefreshTokenDto) {
    const { email } = user;
    const foundUser = await this.userService.findOneByEmail(email);

    if (!foundUser || !foundUser.refreshToken) {
      throw new ForbiddenException('Access denied');
    }

    const { refreshToken } = refreshTokenDto;
    const isRefreshTokenMatches = await AuthService.compareHashed(
      refreshToken,
      foundUser.refreshToken,
    );

    if (!isRefreshTokenMatches) {
      throw new ForbiddenException('Access denied');
    }

    const tokens = await this.getTokens({
      sub: foundUser.id,
      email: foundUser.email,
    });

    await this.updateUserRefreshToken(foundUser.email, tokens.refreshToken);
    return tokens;
  }

  private async updateUserRefreshToken(
    userEmail: UserEntity['email'],
    refreshToken: string,
  ) {
    const hashedRefreshToken = await AuthService.hashData(refreshToken);
    await this.userService.update(userEmail, {
      refreshToken: hashedRefreshToken,
    });
  }

  private async getTokens(payload: JwtPayload) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('JWT_ACCESS_SECRET'),
        expiresIn: this.configService.get('JWT_EXPIRES_IN'),
      }),

      this.jwtService.signAsync(payload, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get('JWT_REFRESH_EXPIRES_IN'),
      }),
    ]);

    return { accessToken, refreshToken };
  }
}
