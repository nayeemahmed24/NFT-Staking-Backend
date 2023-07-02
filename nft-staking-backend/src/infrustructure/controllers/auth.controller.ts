import { Body, Controller, Get, HttpStatus, Post, Req, Res, UseGuards } from '@nestjs/common';
import { Request, Response } from 'express';
import { StakingLogger } from 'src/domain/logger/staking.logger';
import { RolesGuard } from '../authentication/roles.guard';
import { randomUUID } from 'crypto';
import { LoginDto } from 'src/domain/dtos/login.dto';
import { RefreshTokenDto } from 'src/domain/dtos/refresh-token.dto';
import { InitializeAuthCommand } from '../commands/init-auth.command';
import { LoginCommand } from '../commands/login.command';
import { LogoutCommand } from '../commands/logout.command';
import { RefreshTokenCommand } from '../commands/refresh-token.command';
import { Roles } from '../authentication/roles.decorator';
import { UserRoleEnum } from '../enums/user-role.enum';
import { AuthService } from 'src/domain/services/auth.service';

@Controller('auth')
@UseGuards(RolesGuard)
export class AuthController {
  constructor(private readonly logger: StakingLogger,
    private readonly authService: AuthService) {
    this.logger.setContext(AuthController.name);
  }

  @Post('init')
  async initializeAuth(
    @Body() command: InitializeAuthCommand,
    @Res() response: Response,
  ): Promise<any> {
    const correlationId: string = randomUUID();
    this.logger.log(
      correlationId,
      `initializeAuth START for walletAddress: ${command.publicAddress}`,
    );
    const res = await this.authService.initializeAuth(
      correlationId,
      command.publicAddress,
    );

    this.logger.debug(randomUUID(), 'initialized Authentication');

    response.status(HttpStatus.OK);

    this.logger.log(
      correlationId,
      `initializeAuth DONE for walletAddress: ${command.publicAddress}`,
    );
    return response.json(res);
  }

  @Post('login')
  @Roles(UserRoleEnum.Anonymous)
  async login(
    @Req() request: any,
    @Body() command: LoginCommand,
    @Res() response: Response,
  ): Promise<any> {
    const correlationId: string = randomUUID();
    this.logger.log(
      correlationId,
      `login START for walletAddress: ${command.publicAddress}`,
    );

    const authorizationHeaderValue = request.headers['authorization'];
    const loginDto: LoginDto = command;

    const token = await this.authService.login(
      correlationId,
      authorizationHeaderValue,
      loginDto,
    );

    response.status(HttpStatus.OK);

    this.logger.log(
      correlationId,
      `login DONE for walletAddress: ${command.publicAddress}`,
    );
    return response.json(token);
  }

  @Post('logout')
  @Roles(UserRoleEnum.Anonymous, UserRoleEnum.User)
  async logout(
    @Body() command: LogoutCommand,
    @Res() response: Response,
  ): Promise<any> {
    const correlationId: string = randomUUID();
    this.logger.log(
      correlationId,
      `logout START for walletAddress: ${command.publicAddress}`,
    );

    const message = await this.authService.logout(
      correlationId,
      command.publicAddress,
      command.refreshToken,
    );
    response.status(HttpStatus.OK);

    this.logger.log(
      correlationId,
      `logout DONE for walletAddress: ${command.publicAddress}`,
    );
    return response.json(message);
  }

  @Post('refresh_token')
  async refresh_token(
    @Body() command: RefreshTokenCommand,
    @Res() response: Response,
  ): Promise<any> {
    const correlationId: string = randomUUID();
    this.logger.log(
      correlationId,
      `login START for walletAddress: ${command.publicAddress}`,
    );
    const refreshTokenDto: RefreshTokenDto = command;
    const token = await this.authService.refresh(
      correlationId,
      refreshTokenDto,
    );

    response.status(HttpStatus.OK);

    this.logger.log(
      correlationId,
      `login DONE for walletAddress: ${command.publicAddress}`,
    );
    return response.json(token);
  }

}
