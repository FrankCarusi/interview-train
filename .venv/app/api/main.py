from fastapi import Depends, FastAPI, HTTPException, status
from datetime import datetime, timedelta, timezone

from typing import Annotated

from .core import security

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from .models import token 
from .models import user 

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Wellcome to my AI driven self interview application where you will be able to train your interviewing skills"}

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> token.Token:
    user = security.authenticate_user(security.fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return token.Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=user.User)
async def read_users_me(
    current_user: Annotated[user.User, Depends(security.get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[user.User, Depends(security.get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]
