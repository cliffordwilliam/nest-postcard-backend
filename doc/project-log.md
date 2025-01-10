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
username: asd
password: 1234567890123

201
```

```
// test sign up, with existing user, dup post should not be allowed
localhost:3000/authentication/sign-up

body raw json
username: asd
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
username: asd
password: 1234567890123

true
```

```
// test sign in, seee if can sign in with existing user but wrong creds
 localhost:3000/authentication/sign-in

body raw json
username: asd
password: 1234567890123dsadsadsa

{
	"message": "Password does not match",
	"error": "Unauthorized",
	"statusCode": 401
}

btw real cred i used was
{
    "username": "asd",
    "password": "123123123123"
}
```

```bash
npm i @nestjs/jwt @nestjs/config
```

```
// use generator to make the super long str (https://jwtsecret.com/generate)
JWT_SECRET=supersecretkeythatnobodycanguess
// this is the be domain
JWT_TOKEN_AUDIENCE=localhost:3000
// this is the be domein
JWT_TOKEN_ISSUER=localhost:3000
// this is the token lifespan
JWT_ACCESS_TOKEN_TTL=3600
```

```javascript
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

    // New JWT-related environment variables
    JWT_SECRET: Joi.string().required(),
    JWT_TOKEN_AUDIENCE: Joi.string().uri().required(),
    JWT_TOKEN_ISSUER: Joi.string().uri().required(),
    JWT_ACCESS_TOKEN_TTL: Joi.number().integer().positive().default(3600),
  }),
}),
```

```javascript
// grab some from env dump for this config module custom config file
import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => {
  return {
    secret: process.env.JWT_SECRET,
    audience: process.env.JWT_TOKEN_AUDIENCE,
    issuer: process.env.JWT_TOKEN_ISSUER,
    accessTokenTtl: parseInt(process.env.JWT_ACCESS_TOKEN_TTL ?? '3600', 10),
  };
});
```

```javascript
// need to register this to a module, just like in typeorm connection data
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

    // but this time we need to configure jwt, cuz both are 3rd party module init
    // we init this not in root app module, since not all needs this thing, only the iam module
    JwtModule.registerAsync({
      imports: [ConfigModule.forFeature(jwtConfig)],
      useFactory: (configuration: ConfigType<typeof jwtConfig>) => configuration,
      // @Inject(databaseConfig.KEY)
      inject: [jwtConfig.KEY],
    }),

    // or

    import databaseConfig from './config/database.config';

  @Module({
    imports: [
      JwtModule.registerAsync(jwtConfig.asProvider()),
    ],
  })

  // this
  jwtConfig.asProvider()

  // evaluates to this
  {
      imports: [ConfigModule.forFeature(jwtConfig)],
      useFactory: (configuration: ConfigType<typeof jwtConfig>) => configuration,
      // @Inject(databaseConfig.KEY)
      inject: [jwtConfig.KEY],
    }
```

so basically, init the 3rd party jwt module in iam module, and register the custom jwt config in iam parent module

```javascript

    JwtModule.registerAsync(jwtConfig.asProvider()),
    ConfigModule.forFeature(jwtConfig),
```

```javascript
// work on the auth service in iam domain to use the jwt service 3rd parth
// also inject the whole custom config file in here as instance, we can do that since we alr register the custom config in the parent module
    private readonly jwtService: JwtService,
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
```

```javascript
// update to generate token and return it
const accessToken = await this.jwtService.signAsync(
  {
    sub: user.id,
    username: user.username,
  },
  {
    audience: this.jwtConfiguration.audience,
    issuer: this.jwtConfiguration.issuer,
    secret: this.jwtConfiguration.secret,
    expiresIn: this.jwtConfiguration.accessTokenTtl,
  },
);
return {
  accessToken,
};
```

```
// test with insomnia

// login with legal creds
// should get access token
// sign in endpoint is complete

// post
// localhost:3000/authentication/sign-in

// raw json
{
    "username": "asd",
    "password": "123123123123"
}

res
{
	"accessToken": "asdsda"
}
```

```javascript
// use platform res to get hold of cookies and set access token
// that way you should see token in cookies instead
// but i use json only, no need to do this, hard to use later when u use phone client or something
  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  async signIn(
    @Res({ passthrough: true }) response: Response,
    @Body() signInDto: SignInDto,
  ) {
    const accessToken = await this.authService.signIn(signInDto);
    response.cookie('accessToken', accessToken, {
      secure: true,
      httpOnly: true,
      sameSite: true,
    });
  }
```

```bash
// make guard
nest g guard iam/authentication/guards/access-token --flat
```

```javascript
// work on guard

// 📝 access-token.guard.ts
import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import jwtConfig from '../../config/jwt.config';
import { Request } from 'express';
import { REQUEST_USER_KEY } from '../../iam.constants';

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 💡 NOTE: For GraphQL applications, you’d have to use the
    // wrapper GqlExecutionContext here instead.
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }
    try {
      const payload = await this.jwtService.verifyAsync(
        token,
        this.jwtConfiguration,
      );
      request[REQUEST_USER_KEY] = payload;
      console.log(payload);
    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [_, token] = request.headers.authorization?.split(' ') ?? [];
    return token;
  }
}
```

```javascript
// store in const
// iam.constants.ts
export const REQUEST_USER_KEY = 'user';
```

```
// get token

// post
// localhost:3000/authentication/sign-in

body json raw
{
    "username": "asd",
    "password": "123123123123"
}


```

```javascript
// register guard globally to parent module, in providers
{
  provide: APP_GUARD,
  useClass: AccessTokenGuard,
},
```

```
// get coffee
// now everythin is protected with this guard

// get
// localhost:3000/postcards

{
	"message": "Unauthorized",
	"statusCode": 401
}

// try again
// go to auth
// set type to Bearer Token
// set Token val with the one u get just now

should work

{
  sub: 1,
  username: 'asd',
  iat: 1736530527,
  exp: 1736534127,
  aud: 'localhost:3000',
  iss: 'localhost:3000'
}
```

```javascript
// new enums dir in iam dir, put auth-type.enum.ts in it
// none means no guard for that resource
export enum AuthType {
  Bearer,
  None,
}
```

```javascript
// new decorators dir in iam dir, put auth.decorator.ts in it
// set key to the decor, for others to get the val
// val here takes type of that enum, so can only be 2 possible val

import { SetMetadata } from '@nestjs/common';
import { AuthType } from '../enums/auth-type.enum';

export const AUTH_TYPE_KEY = 'authType';

export const Auth = (...authTypes: AuthType[]) =>
  SetMetadata(AUTH_TYPE_KEY, authTypes);
```

```bash
// create new guard in iam authentication.guard.ts

nest g guard iam/authentication/guards/authentication --flat
```

```javascript
// work on auth guard
// need 2 dep
// reflector - grabs decor val with key
// token guard

// need 2 prop
// 1 is default auth type
// the other returns either token guard, or just can activate true (empty guard) for no guard

// now in can activate method
// first grab decor with val with key and also in class and handler scope (get decor val enum by its key)
// if there is no decor, then evaluate to default val, bearer -> protect enum

// now that we have enum
// use it as key to grab the value: can activate method
// call it, see if it:
// throw?
// return true?

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AUTH_TYPE_KEY } from '../decorators/auth.decorator';
import { AuthType } from '../enums/auth-type.enum';
import { AccessTokenGuard } from './access-token.guard';

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private static readonly defaultAuthType = AuthType.Bearer;
  private readonly authTypeGuardMap: Record<
    AuthType,
    CanActivate | CanActivate[]
  > = {
    [AuthType.Bearer]: this.accessTokenGuard,
    [AuthType.None]: { canActivate: () => true },
  };

  constructor(
    private readonly reflector: Reflector,
    private readonly accessTokenGuard: AccessTokenGuard,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const authTypes = this.reflector.getAllAndOverride<AuthType[]>(
      AUTH_TYPE_KEY,
      [context.getHandler(), context.getClass()],
    ) ?? [AuthenticationGuard.defaultAuthType];
    const guards = authTypes.map((type) => this.authTypeGuardMap[type]).flat();
    let error = new UnauthorizedException();

    for (const instance of guards) {
      const canActivate = await Promise.resolve(
        instance.canActivate(context),
      ).catch((err) => {
        error = err;
      });

      if (canActivate) {
        return true;
      }
    }
    throw error;
  }
}

```

```javascript
// replace global token guard with this new auth guard
// make sure to register token guard to be iam provider so that the auth guard can use it
  providers: [
    {
      provide: HashingService,
      useClass: BcryptService,
    },
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard,
    },
    AccessTokenGuard,
    AuthenticationService,
  ],
```

```javascript
// decor the auth controller with auth decor NONE, so that its free to use (sign in up)
@Auth(AuthType.None)
@Controller('authentication')
```

```
// try client with no token to sign in and up
// test sign in

// get token

// post
// localhost:3000/authentication/sign-in

body json raw
{
    "username": "asd",
    "password": "123123123123"
}
```

```javascript
// create dir interfaces in iam
// inside make new file called "active-user-data.interface.ts"
export interface ActiveUserData {
  /**
   * The "subject" of the token. The value of this property is the user ID
   * that granted this token.
   */
  sub: number;

  /**
   * The subject's (user) username.
   */
  username: string;
}

```

```javascript
// create dir decorators in iam
// inside make new file called "active-user.decorator.ts"

// this is to decor param, so we can get the decoded token from req
// use the interface here for strong typing
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { REQUEST_USER_KEY } from '../iam.constants';
import { ActiveUserData } from '../interfaces/active-user-data.interface';

export const ActiveUser = createParamDecorator(
  (field: keyof ActiveUserData | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user: ActiveUserData | undefined = request[REQUEST_USER_KEY];
    return field ? user?.[field] : user;
  },
);


```

```javascript
// when u put decoded token in req, assign this type u made to it
// iam service, sign in method

signAsync(
  {
    sub: dsdsa,
    username: asddsa
  } as ActiveUserData
)
```

```javascript
// try this new decor in find all or something

  @Get()
  findAll(@ActiveUser() user: ActiveUserData) {
    console.log(user);
    return this.postcardsService.findAll();
  }
```
