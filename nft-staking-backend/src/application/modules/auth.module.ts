/* istanbul ignore file */
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthService } from 'src/domain/services/auth.service';
import { TokenService } from 'src/domain/services/token.service';
import { UserService } from 'src/domain/services/user.service';
import { AuthController } from 'src/infrustructure/controllers/auth.controller';
import DBToken from 'src/infrustructure/database/entity/db-token.entity';
import DBUser from 'src/infrustructure/database/entity/db-user.entity';

@Module({
    imports: [JwtModule, ConfigModule,TypeOrmModule.forFeature([DBToken, DBUser]),],
    controllers: [AuthController],
    providers: [JwtService, AuthService, UserService, TokenService],
})
export class AuthModule {}
