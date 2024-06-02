import {
  createParamDecorator,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

export const GetUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;

    if (!authHeader) {
      throw new UnauthorizedException('Authorization header is missing');
    }

    const token = authHeader.split(' ')[1];
    const jwtService = new JwtService();

    try {
      const decoded = jwtService.verify(token, {
        secret: process.env.JWT_SECRET,
      });
      return decoded;
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        // Token is expired, decode it anyway
        const decoded = jwtService.decode(token);
        return decoded;
      }
      throw new UnauthorizedException('Token is expired or invalid');
    }
  },
);
