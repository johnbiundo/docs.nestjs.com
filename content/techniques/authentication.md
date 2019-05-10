### Authentication

Authentication is an **essential** part of most applications. There are a lot of different approaches, strategies, and ways to handle authentication. The approach taken for any project depends on its particular application requirements.  This chapter provides several approaches to authentication that can be adapted to a variety of different requirements.

[Passport](https://github.com/jaredhanson/passport) is the most popular node.js authentication library, well-known by the community and successfully used in many production applications. It's straightforward to integrate this library with a **Nest** application using the built-in Nest-Passport module.

In this chapter, we'll consider two representative use cases, and implement a complete end-to-end authentication solution for each:
* Traditional web application with server-side template-driven HTML pages
* API Server that accepts REST/HTTP requests and returns JSON responses

#### Server-side web application use case

Let's flesh out our requirements a bit. For this use case, we'll have users authenticate with a username and password. Once authenticated, the server will utilize Express sessions so that the user remains "logged in" until they choose to log out.  We'll show how to set up a protected route that is accessible only to an authenticated user.

Let's start by installing the required packages, and building our basic routes. As a side note, for any Passport strategy you choose (there are many available here), you'll always need the `@nestjs/passport` and `passport` libraries. Then, you'll need to install the strategy-specific package that implements the particular authentication strategy you are building.

Passport provides a [passport-local](https://github.com/jaredhanson/passport-local) library that implements a username/password authentication strategy that suits our needs for this use case. Since we are rendering some basic HTML pages, let's also install the versatile and popular [express-handlebars](https://github.com/ericf/express-handlebars) library to make that a little easier.  To support sessions and convenient user feedback during login, we'll also utilize the express-session and connect-flash packages. With these basic requirements in mind, we can now start by creating a brand new Nest application, and installing the dependencies:

```bash
$ nest new auth-sample
$ cd auth-sample
$ npm install --save @nestjs/passport passport passport-local express-handlebars express-session connect-flash @types/express
```

******************
NOTE TO REVIEWERS: We haven't typically included front-end code in the documentation so far.  I think it is useful in this case, as a goal is to provide an end-to-end "template" that users can build from, and to add "depth" to the documentation, especially in areas we know people have struggled.  I would like to get feedback on this.  As well, there's a decision as to whether to include the front-end code in-line in the document, or refer the reader to a repo.  As we can always remove it after the fact, I'm including it in-line in this draft so you can see it and comment.

On a related note, this chapter necessarily diverges from "cats", and as such, I'm proposing a complete repo that can be cloned. Users can refer directly to the repo to run the code documented here.
****************

Let's start by taking care of the templates we'll use to exercise our authentication subsystem.  Following a standard project structure, create the following folder structure:

src
&nbsp;&nbsp;public
&nbsp;&nbsp;&nbsp;&nbsp;views
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;layouts

<!--
<div class="file-tree">
  <div class="item">src</div>
  <div class="children">
    <div class="item">public</div>
    <div class="children">
      <div class="item">views</div>
      <div class="children">
        <div class="item">layouts</div>
      </div>
    </div>
  </div>
</div>
-->

Now, we'll create the following handlebars templates, and configure Nest to use express-handlebars as our view engine.  Refer [here]() for more on handlebars template language.

###### Main layout

Create `main.hbs` in the layouts folder, and add the following code.  This is the outermost container for our views.  Note the `{{{ body}}}` line, which is where each individual view is inserted.  This structure allows us to set up global styles.  In this case, we're taking advantage of Google's well-known [material design lite](https://github.com/google/material-design-lite) component library to style our minimal UI.
```html
<!-- src/public/views/layouts/main.hbs -->
<!DOCTYPE html>
<html>

<head>
  <script src="https://code.getmdl.io/1.3.0/material.min.js"></script>
  <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
  <link rel="stylesheet" href="https://code.getmdl.io/1.3.0/material.indigo-pink.min.css">
  <style>
    .mdl-layout__content {
      padding: 24px;
      flex: none;
    }

    .mdl-textfield__error {
      visibility: visible;
      padding: 5px;
    }

    .mdl-card {
      padding-bottom: 10px;
      min-width: 500px;
    }
  </style>
</head>

<body>
  {{{ body }}}
</body>

</html>
```

###### Home page

Create `home.hbs` in the views folder, and add the following code.  This is the page users land on after authenticating.
```html
<!-- src/public/views/home.hbs -->
<div class="mdl-layout mdl-js-layout mdl-color--grey-100">
  <main class="mdl-layout__content">
    <div class="mdl-card mdl-shadow--6dp">
      <div class="mdl-card__title mdl-color--primary mdl-color-text--white">
        <h2 class="mdl-card__title-text">Welcome {{ user.username }}!</h2>
      </div>
      <div class="mdl-card__supporting-text">
        <div class="mdl-card__actions mdl-card--border">
          <a class="mdl-button" href='/profile'>Get
            Profile</a>
        </div>
      </div>
    </div>
  </main>
</div>
```
###### Login page

Create `login.hbs` in the views folder, and add the following code.  This is the login form
```html
<!-- src/public/views/login.hbs -->
<div class="mdl-layout mdl-js-layout mdl-color--grey-100">
  <main class="mdl-layout__content">
    <div class="mdl-card mdl-shadow--6dp">
      <div class="mdl-card__title mdl-color--primary mdl-color-text--white">
        <h2 class="mdl-card__title-text">Nest Cats</h2>
      </div>
      <div class="mdl-card__supporting-text">
        <form action="/login" method="post">
          <div class="mdl-textfield mdl-js-textfield">
            <input class="mdl-textfield__input" type="text" name="username" id="username" />
            <label class="mdl-textfield__label" for="username">Username</label>
          </div>
          <div class="mdl-textfield mdl-js-textfield">
            <input class="mdl-textfield__input" type="password" name="password" id="password" />
            <label class="mdl-textfield__label" for="password">Password</label>
          </div>
          <div class="mdl-card__actions mdl-card--border">
            <button class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect">Log In</button>
            <span class="mdl-textfield__error">{{ message }}
          </div>
        </form>
      </div>
    </div>
  </main>
</div>
```
###### Profile page

Create `profile.hbs` in the views folder and add the following code.  This page displays details about the logged in user.  It's rendered on our protected route.
```html
<!-- src/public/views/profile.hbs -->
<div class="mdl-layout mdl-js-layout mdl-color--grey-100">
  <main class="mdl-layout__content">
    <div class="mdl-card mdl-shadow--6dp">
      <div class="mdl-card__title mdl-color--primary mdl-color-text--white">
        <h2 class="mdl-card__title-text">About {{ user.username }}</h2>
      </div>
      <div>
        <figure><img src="http://lorempixel.com/400/200/cats/{{user.pet.picId}}">
          <figcaption>{{user.username}}'s friend {{user.pet.name}}</figcaption>
        </figure>
        <div class="mdl-card__actions mdl-card--border">
          <a class="mdl-button" href='/logout'>Log Out</a>
        </div>
      </div>
    </div>
  </main>
</div>
```

###### Set up view engine
Now let's tell Nest to use express-handlebars as our view engine.  Modify the `main.ts` file so that it looks like this:
````typescript
// main.ts
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import { AppModule } from './app.module';
import * as exphbs from 'express-handlebars';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const viewsPath = join(__dirname, '/public/views');
  app.engine('.hbs', exphbs({ extname: '.hbs', defaultLayout: 'main' }));
  app.set('views', viewsPath);
  app.set('view engine', '.hbs');

  await app.listen(3000);
}
bootstrap();
````

###### Authentication routes
The final step in this section is setting up our routes.  Modify `src\app.controller.ts` so that it looks like this:
````typescript
// src/app.controller.ts
import { Controller, Get, Post, Request } from '@nestjs/common';
import { Response } from 'express';

@Controller()
export class AppController {
  @Get('/')
  index(@Request() req, @Res() res: Response) {
    res.render('login');
  }

  @Post('/login')
  login(@Request() req, @Res() res: Response) {
    res.redirect('/home');
  }

  @Get('/home')
  getHome(@Request() req, @Res() res: Response) {
    res.render('home');
  }

  @Get('/profile')
  getProfile(@Request() req, @Res() res: Response) {
    res.render('profile');
  }

  @Get('/logout')
  logout(@Request() req, @Res() res: Response) {
    res.redirect('/');
  }
}
````

At this point, you should be able to browse to <a href="http://localhost:3000/">http://locahost:3000</a> and click through the basic UI.

###### Implementing Passport strategies

We're now ready to implement the authorization feature. Let's start with an overview of the process used for **any** Passport strategy.  It's helpful to think of Passport as a mini framework in itself. The beauty of the framework is that it abstracts authentication into a few basic things that you customize based on the strategy you're implementing.  The nest-passport module wraps this framework in a Nest style package.  In vanilla passport, you configure a strategy by providing two things:
1. A set of options that are specific to that strategy.
2. A "verify callback", which is where you tell Passport how to interact with your user store (where you manage user accounts) and either create or verify whether a user exists, and if their credentials are valid.

In Nest, you achieve these functions by extending the `PassportStrategy` class.  You pass options by calling the `super()` method in your subclass.  You provide the verify callback by implementing a `validate` method in your subclass.

As mentioned, we'll utilize the passport-local strategy for this use-case.  We'll do that below.  Start by generating an `auth module` and in it, an `auth service`:

````bash
$ nest g module auth
$ nest g service auth
````

As we implement the `auth service`, you'll see that we'll want to also have a `users service`, so let's generate that module and service now:

````bash
$ nest g module users
$ nest g service users
````

Replace the default contents of these generated files as shown below.

In our prototype, the `UsersService` simply maintains a hard-coded in-memory list of users, and a method to retrieve one by username.  In a real app, this is where you'd build you user model and persistence layer, using your library of choice (e.g., TypeORM, Sequelize, etc.).

````typescript
// src/users/users.service.ts
import { Injectable } from '@nestjs/common';

@Injectable()
export class UsersService {
  private readonly users;

  constructor() {
    this.users = [
      {
        username: 'john',
        password: 'changeme',
        pet: { name: 'alfred', picId: 1 },
      },
      {
        username: 'chris',
        password: 'secret',
        pet: { name: 'gopher', picId: 2 },
      },
      {
        username: 'maria',
        password: 'guess',
        pet: { name: 'jenny', picId: 3 },
      },
    ];
  }

  async findOne(username): Promise<any> {
    return this.users.filter(user => user.username === username)[0];
  }
}
````

In the UsersModule, the only change is to add the `UsersService` to the exports array of the `@Module` decorator so that it is visible outside this module (we'll want to use it in our `AuthService`).
````typescript
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';

@Module({
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
````

Our `AuthService` has the job of retrieving a user and verifying the password.  Of course in a real application, you wouldn't store a password in plain text. You'd instead use a library like [bcrypt](), with a salted one-way hash algorithm. With that approach, you'd only store hashed passwords, and then compare the stored password to a hashed version of the **incoming** password, thus never storing or exposing user passwords in plain text. To keep our prototype simple, we violate that absolute mandate and use plain text.  **Don't do this in your real app!**

The Passport library expects us to return a full user if the validation succeeds, or a null if it fails (failure could be either the user is not found, or the password does not match). Upon successful validation, Passport then takes care of a few details for us, which we'll explore later on in the Sessions section.

````typescript
// src/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) {}

  async validateUser(username, password): Promise<any> {
    const user = await this.usersService.findOne(username);
    return user && user.password === password ? user : null;
  }
}
````

And finally, we just need to update our `AuthModule` so it imports the `UsersModule`.

````typescript
// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [UsersModule],
  providers: [AuthService],
})
export class AuthModule {}
````
Our app will function now, but remains slightly broken until we complete a few more steps.  You can navigate to <a href="http://localhost:3000/">http://locahost:3000</a> and still move around without logging in (after all, we haven't implemented our Passport Local strategy yet.  We'll get there momentarily).  Notice that if you **do** login (refer to the `UsersService` for username/passwords you can test with), the profile page now provides some (but not all) information about a "logged in" user.


#### Bearer strategy

As has been said already, firstly, we'll implement [passport-http-bearer](https://github.com/jaredhanson/passport-http-bearer) library. Bearer tokens are typically used to protect API endpoints, and are often issued using OAuth 2.0. The HTTP Bearer authentication strategy authenticates users using a bearer token.

Let's start by creating the `AuthService` class that will expose a single method, `validateUser()` which responsibility is to query user using provided bearer **token**.

```typescript
@@filename(auth.service)
import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) {}

  async validateUser(token: string): Promise<any> {
    // Validate if token passed along with HTTP request
    // is associated with any registered account in the database
    return await this.usersService.findOneByToken(token);
  }
}
@@switch
import { Injectable, Dependencies } from '@nestjs/common';
import { UsersService } from '../users/users.service';

@Injectable()
@Dependencies(UsersService)
export class AuthService {
  constructor(usersService) {
    this.usersService = usersService;
  }

  async validateUser(token) {
    // Validate if token passed along with HTTP request
    // is associated with any registered account in the database
    return await this.usersService.findOneByToken(token);
  }
}
```

The `validateUser()` method takes `token` as an argument. This token is extracted from `Authorization` header that has been passed along with HTTP request. The `findOneByToken()` method's responsibility is to validate if passed token truly exists and is associated with any registered account in the database.

Once `AuthService` class is done, we have to create a corresponding **strategy** that passport will use to authenticate requests.

```typescript
@@filename(http.strategy)
import { Strategy } from 'passport-http-bearer';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class HttpStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super();
  }

  async validate(token: string) {
    const user = await this.authService.validateUser(token);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
@@switch
import { Strategy } from 'passport-http-bearer';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, Dependencies, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
@Dependencies(AuthService)
export class HttpStrategy extends PassportStrategy(Strategy) {
  constructor(authService) {
    super();
    this.authService = authService;
  }

  async validate(token) {
    const user = await this.authService.validateUser(token);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
```

The `HttpStrategy` uses `AuthService` to validate the token. When the token is valid, passport allows further request processing. Otherwise, the user receives `401 Unauthorized` response.

Afterwards, we can create the `AuthModule`.

```typescript
@@filename(auth.module)
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { HttpStrategy } from './http.strategy';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [UsersModule],
  providers: [AuthService, HttpStrategy],
})
export class AuthModule {}
```

> warning **Notice** In order to make use of `UsersService`, the `AuthModule` imports `UsersModule`. The internal implementation is unimportant here and heavily depends on your technical project requirements (e.g. database).

Then, you can simply use the `AuthGuard` wherever you want to enable the authentication.

```typescript
@Get('users')
@UseGuards(AuthGuard('bearer'))
findAll() {
  return [];
}
```

The `@AuthGuard()` is imported from `@nestjs/passport` package. Also, `bearer` is a name of the strategy that passport will make use of. Let us check if endpoint is effectively secured. To ensure that everything work correctly, we'll perform a GET request to the `users` resource without setting a valid token.

```bash
$ curl localhost:3000/users
```

Application should respond with `401 Unauthorized` status code and following response body:

```typescript
"statusCode": 401,
"error": "Unauthorized"
```

If you create a valid token beforehand and pass it along with the HTTP request, the application will respectively identify a user, attach its object to the request, and allow further request processing.

```bash
$ curl localhost:3000/users -H "Authorization: Bearer TOKEN"
```

#### Default strategy

To determine default passport behavior, you can register the `PassportModule`.

```typescript
@@filename(auth.module)
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { HttpStrategy } from './http.strategy';
import { UsersModule } from '../users/users.module';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'bearer' }),
    UsersModule,
  ],
  providers: [AuthService, HttpStrategy],
  exports: [PassportModule, AuthService]
})
export class AuthModule {}
```

Once you set `defaultStrategy`, you no longer need to manually pass the strategy name in the `@AuthGuard()` decorator.

```typescript
@Get('users')
@UseGuards(AuthGuard())
findAll() {
  return [];
}
```

> warning **Notice** Keep in mind that either `PassportModule` or `AuthModule` has to be imported by every module that makes use of the `AuthGuard`.

#### User object

When request is validated correctly, the user entity will be attached to the request object and accessible through `user` property (e.g. `req.user`). To change the property name, set `property` of the options object.

```typescript
PassportModule.register({ property: 'profile' });
```

#### Customize passport

Depending on the strategy that is being used, passport takes a bunch of properties that shape the library behavior. Use `register()` method to pass down options object directly to the passport instance.

```typescript
PassportModule.register({ session: true });
```

#### Inheritance

In most cases, `AuthGuard` will be sufficient. However, in order to adjust either default error handling or authentication logic, you can extend the class and override methods within a subclass.

```typescript
import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) {
    // Add your custom authentication logic here
    // for example, call super.logIn(request) to establish a session.
    return super.canActivate(context);
  }

  handleRequest(err, user, info) {
    if (err || !user) {
      throw err || new UnauthorizedException();
    }
    return user;
  }
}
```

> info **Hint** In order to use your custom `JwtAuthGuard`, you must add it as a guard to your specific routes (e.g., `@UseGuards(JwtAuthGuard)`)

#### JWT strategy

A second described approach is to authenticate endpoints using a **JSON web token** (JWT). To implement a JWT-based authentication flow, we need to install required packages.

```bash
$ npm install --save @nestjs/jwt passport-jwt
```

Once the installation process is done, we can focus on `AuthService` class. We need to switch from the token validation to a payload-based validation logic as well as provide a way to create a JWT token for the particular user which then could be used to authenticate the incoming request.

```typescript
@@filename(auth.service)
import { JwtService } from '@nestjs/jwt';
import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async signIn(): Promise<string> {
    // In the real-world app you shouldn't expose this method publicly
    // instead, return a token once you verify user credentials
    const user: JwtPayload = { email: 'user@email.com' };
    return this.jwtService.sign(user);
  }

  async validateUser(payload: JwtPayload): Promise<any> {
    return await this.usersService.findOneByEmail(payload.email);
  }
}
@@switch
import { JwtService } from '@nestjs/jwt';
import { Injectable, Dependencies } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
@Dependencies(UsersService, JwtService)
export class AuthService {
  constructor(usersService, jwtService) {
    this.usersService = usersService;
    this.jwtService = jwtService;
  }

  async signIn() {
    // In the real-world app you shouldn't expose this method publicly
    // instead, return a token once you verify user credentials
    const user = { email: 'user@email.com' };
    return this.jwtService.sign(user);
  }

  async validateUser(payload) {
    return await this.usersService.findOneByEmail(payload.email);
  }
}
```

> info **Hint** The `JwtPayload` is an interface with a single property, an `email`, and represents decoded JWT token.

In order to simplify an example, we created a fake user. The second step is to create a corresponding `JwtStrategy`.

```typescript
@@filename(jwt.strategy)
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from './auth.service';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'secretKey',
    });
  }

  async validate(payload: JwtPayload) {
    const user = await this.authService.validateUser(payload);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
@@switch
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from './auth.service';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, Dependencies, UnauthorizedException } from '@nestjs/common';

@Injectable()
@Dependencies(AuthService)
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(authService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'secretKey',
    });
    this.authService = authService;
  }

  async validate(payload, done) {
    const user = await this.authService.validateUser(payload);
    if (!user) {
      return done(new UnauthorizedException(), false);
    }
    done(null, user);
  }
}
```

The `JwtStrategy` uses `AuthService` to validate the decoded payload. When the payload is valid (user exists), passport allows further request processing. Otherwise, the user receives `401 (Unauthorized)` response.

Afterward, we can move to the `AuthModule`.

```typescript
@@filename(auth.module)
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { UsersModule } from '../users/users.module';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secretOrPrivateKey: 'secretKey',
      signOptions: {
        expiresIn: 3600,
      },
    }),
    UsersModule,
  ],
  providers: [AuthService, JwtStrategy],
  exports: [PassportModule, AuthService],
})
export class AuthModule {}
```

> info **Hint** In order to make use of `UsersService`, the `AuthModule` imports `UsersModule`. The internal implementation is unimportant here. Besides, `JwtModule` has been registered statically. To switch to asynchronous configuration, read more [here](https://github.com/nestjs/passport).

Both expiration time and `secretKey` are hardcoded (in a real-world application you should rather consider using environment variables).

Then, you can simply use the `AuthGuard` wherever you want to enable the authentication.

```typescript
@Get('users')
@UseGuards(AuthGuard())
findAll() {
  return [];
}
```

Let us check if endpoint is effectively secured. To ensure that everything work correctly, we'll perform a GET request to the `users` resource without setting a valid token.

```bash
$ curl localhost:3000/users
```

Application should respond with `401 Unauthorized` status code and following response body:

```typescript
"statusCode": 401,
"error": "Unauthorized"
```

If you create a valid token beforehand and pass it along with the HTTP request, the application will respectively identify a user, attach its object to the request, and allow further request processing.

```bash
$ curl localhost:3000/users -H "Authorization: Bearer TOKEN"
```

#### Example

A full working example is available [here](https://github.com/nestjs/nest/tree/master/sample/19-auth).

#### Multiple strategies

Usually, you'll end up with single strategy reused across the whole application. However, there might be cases when you'd prefer to use different strategies for different scopes. In the case of multiple strategies, pass the second argument to the `PassportStrategy` function. Generally, this argument is a name of the strategy.

```typescript
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt')
```

In above example, the `jwt` becomes the name of the `JwtStrategy`. Afterward, you can use `@AuthGuard('jwt')`, just the same as before.

#### GraphQL

In order to use `AuthGuard` together with [GraphQL](/graphql/quick-start), you have to extend the built-in `AuthGuard` class and override `getRequest()` method.

```typescript
@Injectable()
export class GqlAuthGuard extends AuthGuard('jwt') {
  getRequest(context: ExecutionContext) {
    const ctx = GqlExecutionContext.create(context);
    return ctx.getContext().req;
  }
}
```

We assumed that `req` (request) has been passed as a part of the context value. We have to set this behavior in the module settings.

```typescript
GraphQLModule.forRoot({
  context: ({ req }) => ({ req }),
});
```

And now, context value will have `req` property.
