import { Controller, Get, UseGuards } from '@nestjs/common';
import { AccessTokenGuard } from '../common/guards/access-token.guard';

@Controller('user')
export class UserController {
  @UseGuards(AccessTokenGuard)
  @Get()
  getMockUser() {
    return {
      id: 1,
      name: 'Alex',
    };
  }
}
