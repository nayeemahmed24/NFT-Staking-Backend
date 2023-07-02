import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { AppController } from '../../infrustructure/controllers/app.controller';
import { AppService } from '../../domain/services/app.service';
import { WalletAddressMiddleware } from '../middlewares/wallet-address.middleware';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as Joi from 'joi';
import { TypeOrmModule } from '@nestjs/typeorm';
import DBUser from 'src/infrustructure/database/entity/db-user.entity';
import DBToken from 'src/infrustructure/database/entity/db-token.entity';
import { JwtService } from '@nestjs/jwt';
import { AuthModule } from './auth.module';
import { LoggerModule } from './logger.module';


const ENV = process.env.NODE_ENV;
@Module({
  imports: [
    AuthModule,
    LoggerModule,
    ConfigModule.forRoot({
      validationSchema: Joi.object({
        DATABASE_HOST: Joi.string().required(),
        DATABASE_PORT: Joi.number().required(),
        DATABASE_USER: Joi.string().required(),
        DATABASE_PASSWORD: Joi.string().required(),
        DATABASE_NAME: Joi.string().required(),
      }),
      isGlobal: true,
      envFilePath: `${process.cwd()}/env/${ENV}.env`,
      load: [],
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('DATABASE_HOST'),
        port: configService.get('DATABASE_PORT'),
        username: configService.get('DATABASE_USER'),
        password: configService.get('DATABASE_PASSWORD'),
        database: configService.get('DATABASE_NAME'),
        entities: [
          DBUser,
          DBToken,
        ],
        synchronize: true, // never make it true in Production, otherwise you might lose data
        logging: true,
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AppController],
  providers: [AppService, JwtService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): any {
    consumer.apply(WalletAddressMiddleware).forRoutes('*');
  }
}
