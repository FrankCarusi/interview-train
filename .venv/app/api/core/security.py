from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from ..models import user

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "first_name": "John",
        "last_name": " Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "first_name": "Alice",
        "last_name": " Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

class UserInDB(user.User):
    hashed_password: str

def fake_hash_password(password: str):
    return "fakehashed" + password

def fake_decode_token(token):
    return user.User(
        username=token + "Fakedecoded", email="bob@builder.com", first_name="Bob", last_name="Builder"
    )


def get_user(db, username: str): ## needs to be changed to work with actual database
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

async def get_current_active_user(
        current_user: Annotated[user.User, Depends(get_current_user)]
):
    print(current_user.disabled)
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return current_user







