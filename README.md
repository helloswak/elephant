# Welcome to Api

This content is for our new guppy.
this API is built in the following way


## Class list

1. User
```
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(42), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
```


## Endpoint list

1. registration
Method: POST

2. login
Method: POST

3. /password/forget
Method: GET

4. /token/refresh
Method: POST

5. feed
Method: GET

## Contributing

The Swak Team
 
