import { JwtPayload } from './types/jwt-payload.type';

import { AuthService } from './auth.service';
import { Body, Controller, Param, Post, Req, UseGuards } from '@nestjs/common';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AtGuard, RtGuard } from '../common/guards';
import { GetCurrentUser, Public } from '../common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public() // Prevent using AtGuard by using Public Decorator
  @Post('signup')
  signUpLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signUp(authDto);
  }

  @Public()
  @Post('signin')
  signInLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signIn(authDto);
  }

  // Access with Access Token
  @Post('logout')
  logout(@GetCurrentUser('sub') userId: number) {
    this.authService.logout(userId);
  }

  // Access with Refresh Token
  @Public()
  @UseGuards(RtGuard) // RtStrategy
  @Post('refresh')
  refreshToken(@GetCurrentUser() user: JwtPayload) {
    return this.authService.refreshToken(parseInt(user.sub), user.refreshToken);
  }
}
