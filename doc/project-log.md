```bash
nest new
```

```bash
nest g resource postcards
```

```bash
nest g resource users
```

```bash
npm run start:dev
```

# Install PostgreSQL

[odin proj install postgresql](https://www.theodinproject.com/lessons/nodejs-installing-postgresql)

# Create database

[odin proj using postgresql](https://www.theodinproject.com/lessons/nodejs-using-postgresql)

# Exit psql with '\q'

```bash
npm i @nestjs/typeorm typeorm pg
```

```bash
npm i @nestjs/config
```

```
<!-- in .env -->
<!-- dump all env here does not matter, we grab per module later -->

<!-- db creds, follow odin -->
DATABASE_USER=dsdsadsa
DATABASE_PASSWORD=321321dasdsa
DATABASE_NAME=dasdsa
DATABASE_PORT=321321
DATABASE_HOST=dsadsadsa
```

```
<!-- in .gitignore -->
<!-- ignore .env always -->

# Env
*.env
```

```bash
npm i @hapi/joi
npm i --save-dev @types/hapi__joi
```

```javascript
// validate whole .env here
// import like this else it wont work "import * as Joi from '@hapi/joi';"
    ConfigModule.forRoot({
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
```

```javascript
// this is the global app config module
// 1. grab some from env
// 2. transform it + default vals
// /src/config/app.config.ts File
import { registerAs } from '@nestjs/config';

export default registerAs('database', () => ({
  environment: process.env.NODE_ENV || 'development',
  database: {
    host: process.env.DATABASE_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT, 10) || 5432,
    username: process.env.DATABASE_USER || 'postgres',
    password: process.env.DATABASE_PASSWORD || '',
    name: process.env.DATABASE_NAME || 'database',
  },
}));
```

```javascript
// register app config in root app module
// in imports
// Load a namespaced configuration with the load property of the forRoot() method's options object
    ConfigModule.forRoot({
      load: [appConfig],
    }),
```

```javascript
// setup connection with factory method, inject app custom config
// register app config to parent root module
// in imports
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
      // @Inject(databaseConfig.KEY)
      inject: [appConfig.KEY],
    }),
```

```bash
// look for this to ensure connection is ok
[Nest] 23463  - 01/08/2025, 10:11:25 PM     LOG [InstanceLoader] TypeOrmModule dependencies initialized +9ms
```

```javascript
// setup user entity
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  username: string;

  @Column()
  password: string;
}
```

```javascript
// register entity to parent module
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
```

# Check dbeaver if user table is made

```javascript
// install depdendencies
npm i bcrypt
npm i @types/bcrypt -D
```

```bash
// generate IAM module & Hashing / BCrypt files
// iam = identity and access management
nest g module iam
nest g service iam/hashing
// flat means bcrypt at end of path is file, not dir then hold file in it
nest g service iam/hashing/bcrypt --flat
```

```javascript
// update iam module, token = parent class, value = child (switch to ur desired class, this one implement brypt)

import { Module } from '@nestjs/common';
import { BcryptService } from './hashing/bcrypt.service';
import { HashingService } from './hashing/hashing.service';

@Module({
  providers: [
    {
      provide: HashingService,
      useClass: BcryptService,
    },
  ],
})
export class IamModule {}
```

```javascript
// the parent

import { Injectable } from '@nestjs/common';

@Injectable()
export abstract class HashingService {
  abstract hash(data: string | Buffer): Promise<string>;
  abstract compare(data: string | Buffer, encrypted: string): Promise<boolean>;
}
```

```javascript
// the child
// bcrypt implement

import { Injectable } from '@nestjs/common';
import { compare, genSalt, hash } from 'bcrypt';
import { HashingService } from './hashing.service';

@Injectable()
export class BcryptService implements HashingService {
  async hash(data: string | Buffer): Promise<string> {
    const salt = await genSalt();
    return hash(data, salt);
  }

  compare(data: string | Buffer, encrypted: string): Promise<boolean> {
    return compare(data, encrypted);
  }
}

```

```bash
// Generate Authentication Controller
nest g controller iam/authentication
```

```bash
// Generate Authentication Service
nest g service iam/authentication
```

```bash
// Let’s generate the DTO (or Data Transfer Object) classes for 2 endpoints
// we plan on exposing in our application: SignInDto and SignUpDto
nest g class iam/authentication/dto/sign-in.dto --no-spec --flat
nest g class iam/authentication/dto/sign-up.dto --no-spec --flat
```

```bash
// Install dependencies needed
npm i class-validator class-transformer
```

```bash
// 📝 main.ts file - add ValidationPipe
app.useGlobalPipes(new ValidationPipe());
```

```javascript
// src/common/common.module.ts
// register global stuff here
// ref: Using Metadata to Build Generic Guards or Interceptors
// ref: Understanding Binding Techniques
nest g mo common
```

```javascript
// src/common/common.module.ts
// register global stuff here
// ref: Using Metadata to Build Generic Guards or Interceptors
// ref: Understanding Binding Techniques
import { Module, ValidationPipe } from '@nestjs/common';
import { APP_PIPE } from '@nestjs/core';

@Module({
  providers: [
    {
      provide: APP_PIPE,
      useFactory: () => {
        return new ValidationPipe({
          whitelist: true,
          transform: true,
          forbidNonWhitelisted: true,
        });
      },
    },
  ],
})
export class CommonModule {}
```

```javascript
// update dto

// 📝 signup.dto.ts
import { IsString, MinLength } from 'class-validator';

export class SignInDto {
  @IsString()
  username: string;

  @MinLength(10)
  password: string;
}


// 📝 signin.dto.ts
import { IsString, MinLength } from 'class-validator';

export class SignInDto {
  @IsString()
  username: string;

  @MinLength(10)
  password: string;
}

```

```javascript
// work on auth service in iam module
import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { HashingService } from '../hashing/hashing.service';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    private readonly hashingService: HashingService,
  ) {}

  async signUp(signUpDto: SignUpDto) {
    try {
      const user = new User();
      user.username = signUpDto.username;
      user.password = await this.hashingService.hash(signUpDto.password);

      await this.usersRepository.save(user);
    } catch (err) {
      const pgUniqueViolationErrorCode = '23505'; // save this in dedicated const, to be use else where
      if (err.code === pgUniqueViolationErrorCode) {
        throw new ConflictException();
      }
      throw err;
    }
  }

  async signIn(signInDto: SignInDto) {
    const user = await this.usersRepository.findOneBy({
      username: signInDto.username,
    });
    if (!user) {
      throw new UnauthorizedException('User does not exists');
    }
    const isEqual = await this.hashingService.compare(
      signInDto.password,
      user.password,
    );
    if (!isEqual) {
      throw new UnauthorizedException('Password does not match');
    }
    // TODO: return jwt later
    return true;
  }
}
```

```javascript
// work on auth controller in iam module
import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';

@Controller('authentication')
export class AuthenticationController {
  constructor(private readonly authService: AuthenticationService) {}

  @Post('sign-up')
  signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  signIn(@Body() signInDto: SignInDto) {
    return this.authService.signIn(signInDto);
  }
}
```

```javascript
// work on iam module
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { AuthenticationController } from './authentication/authentication.controller';
import { AuthenticationService } from './authentication/authentication.service';
import { BcryptService } from './hashing/bcrypt.service';
import { HashingService } from './hashing/hashing.service';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [
    {
      provide: HashingService,
      useClass: BcryptService,
    },
    AuthenticationService,
  ],
  controllers: [AuthenticationController],
})
export class IamModule {}
```

```
// test sign in, when there is no saved users yet
localhost:3000/authentication/sign-in

body raw json
username: dsa
password: 1234567890123

{
	"message": "User does not exists",
	"error": "Unauthorized",
	"statusCode": 401
}
```

```
// test sign up, with the same body
localhost:3000/authentication/sign-up

body raw json
username: dsa
password: 1234567890123

201
```

```
// test sign up, with existing user, dup post should not be allowed
localhost:3000/authentication/sign-up

body raw json
username: dsa
password: 1234567890123

{
	"message": "Conflict",
	"statusCode": 409
}
```

```
// test sign in, seee if can sign in with existing user
 localhost:3000/authentication/sign-in

body raw json
username: dsa
password: 1234567890123

true
```

```
// test sign in, seee if can sign in with existing user but wrong creds
 localhost:3000/authentication/sign-in

body raw json
username: dsa
password: 1234567890123dsadsadsa

{
	"message": "Password does not match",
	"error": "Unauthorized",
	"statusCode": 401
}
```
