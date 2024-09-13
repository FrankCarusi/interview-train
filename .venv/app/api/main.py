from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel

from typing import Annotated

from .core import security

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Wellcome to my AI driven self interview application where you will be able to train your interviewing skills"}

@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = security.fake_users_db.get(form_data.username)

    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = security.UserInDB(**user_dict)
    hashed_password = security.fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: Annotated[str, Depends(security.get_current_user)]):
    return current_user