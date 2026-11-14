import { Body, Controller, Get, Post, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { JwtAuthGuard } from './jwt-auth.guard.js';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(
    @Body()
    body: {
      name: string;
      email: string;
      pass: string;
      accountType?: 'CUSTOMER' | 'SHOP_OWNER';
      shopName?: string;
    },
  ) {
    return this.authService.register(body);
  }

  @Post('login')
  async login(@Body() body: { email: string; pass: string }) {
    return this.authService.login(body.email, body.pass);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req: any) {
    return req.user;
  }
}
