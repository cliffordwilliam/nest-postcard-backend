import * as Joi from '@hapi/joi';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigType } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import appConfig from './config/app.config';
import { PostcardsModule } from './postcards/postcards.module';
import { UsersModule } from './users/users.module';
import { IamModule } from './iam/iam.module';
import { CommonModule } from './common/common.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [appConfig],
      validationSchema: Joi.object({
        NODE_ENV: Joi.string()
          .valid('development', 'production', 'test', 'staging')
          .default('development'),
        DATABASE_HOST: Joi.string().hostname().required(),
        DATABASE_PORT: Joi.number().port().required(),
        DATABASE_USER: Joi.string().required(),
        DATABASE_PASSWORD: Joi.string().required(),
        DATABASE_NAME: Joi.string().required(),
      }),
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule.forFeature(appConfig)],
      useFactory: (configuration: ConfigType<typeof appConfig>) => ({
        type: 'postgres',
        host: configuration.database.host,
        port: configuration.database.port,
        username: configuration.database.username,
        password: configuration.database.password,
        database: configuration.database.name,
        autoLoadEntities: true,
        synchronize: true,
      }),
      inject: [appConfig.KEY],
    }),
    PostcardsModule,
    UsersModule,
    IamModule,
    CommonModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
