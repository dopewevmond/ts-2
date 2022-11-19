# jwt

### Protected routes

GET `/`<br>
Requires authorization token with role: `admin` or `member`.<br>
On success, returns a list of books in this format
```
books = [
  {
    "author": "Chinua Achebe",
    "country": "Nigeria",
    "language": "English",
    "pages": 209,
    "title": "Things Fall Apart",
    "year": 1958
  }
]
```
<br>

POST `/`<br>
Requires authorization token with role: `admin`.<br>
If user without `admin` role tries to access this endpoint, returns a status code of `401`<br>
Request body should be json with the format below else a `400` is returned.
```
  {
    "author": "Chinua Achebe",
    "country": "Nigeria",
    "language": "English",
    "pages": 209,
    "title": "Things Fall Apart",
    "year": 1958
  }
 ```
 
On success, returns with 201
```
  {
    "message": "book uploaded"
  }
```


<br><br>
## Authentication and Authorization<hr>
Everytime the server starts a user with an `admin` role is created with credentials
```
  Email = "johndoe@example.com"
  Password = "password"
```
New users can be created using the `/auth/register` route but they will have a role of `member`.<br>


POST `/auth/login`<br>
Authenticates a user with an email and password<br>
Request body should be json with the format below else return status code of `401`
```
  {
    "email": "johndoe@example.com",
    "password": "password"
  }
 ```
 
On success, returns an access token and a refresh token with `200`
```
  {
    "accessToken": "<some-access-token>",
    "refreshToken": "<some-refresh-token>"
  }
```


POST `/auth/register`<br>
Creates a new user. Cannot register with an already existing email<br>
Request body should be json with the format below else return status code of `400`
```
  {
    "email": "jane@example.com",
    "password": "randomword"
  }
 ```
 
On success, returns with `201`
```
  {
    "message": "user created successfully"
  }
```

POST `/auth/reset-password-request`<br>
Returns a password reset token<br>
Request body should be json with the format below else return status code of `400`.<br>
If a request is sent more than once to this endpoint, all the previous tokens will be invalidated. Only the most recent token can be used to change the password.<br>
`Email`: the email whose password is to be changed
```
  {
    "email": "jane@example.com"
  }
 ```
 
On success, returns a password reset token with `200`
```
  {
    "passwordResetToken": <some-password-reset-token>
  }
```

POST `/auth/reset-password`<br>
Used to reset a user's password<br>
Request body should be json with the format below else return status code of `400`.<br>
If a request is sent more than once to this endpoint, all the previous tokens will be invalidated. Only the most recent token can be used to change the password.<br>
`resetToken`: password token obtained from the `/auth/reset-password-request` endpoint<br>
`newPassword`: preferred new password
```
  {
    "resetToken": <password-reset-token>,
    "newPassword": <the-new-password>
  }
 ```
 
On success, returns with `200`
```
  {
    "message": "password changed successfully"
  }
```

POST `/auth/refresh-token`<br>
Used to reset a user's password<br>
Request body should be json with the format below else return status code of `400`.<br>
If a request is sent more than once to this endpoint, all the previous tokens will be invalidated. Only the most recent token can be used to change the password.<br>
`refreshToken`: refresh token obtained after logging in
```
  {
    "refreshToken": <refresh-token>
  }
 ```
 
On success, returns a new access token and a new refresh token with `200`
```
  {
    "accessToken": "<some-new-access-token>",
    "refreshToken": "<some-new-refresh-token>"
  }
```

POST `/auth/logout`<br>
Invalidates a user's access token prematurely.
User needs to be logged in else a `401` is returned.<br>
 
On success, returns a `200`
```
  {
    "message": "logged out successfully"
  }
```
