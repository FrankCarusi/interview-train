from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Wellcome to my AI driven self interview application where you will be able to train your interviewing skills"}