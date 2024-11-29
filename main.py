from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
import mysql.connector
import csv
from pydantic import BaseModel
from typing import List
import io
import pandas as pd
from jose import JWTError,jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import cryptocode
from io import StringIO
from datetime import datetime,timedelta
import logging

logger = logging.getLogger("uvicorn")
logger.setLevel(logging.ERROR)

class Asset(BaseModel):
    asset_id: str
    asset_name: str
    user_id: int
    username: str
    asset_condition: str
    asset_location: str

class User(BaseModel):
    user_id:int
    username: str
    asset_id: int
    hash_password: str
    role: str

class Token(BaseModel):
    access_token: str
    bearer_type: str

class TokenData(BaseModel):
    user_id:int
    role:str

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 450

def get_connect():
    connection = mysql.connector.connect(
        host="localhost",
        port="3307",
        user="root",
        password="root",
        database="sample"
    )
    return connection

app = FastAPI()
auth_scheme= OAuth2PasswordBearer(tokenUrl="token")

def crypt_decode(password:str):
    decoded= cryptocode.decrypt(password,"4")
    return decoded

def create_access_token(data:dict,expires_delta: timedelta=None):
    to_encode= data.copy()
    if expires_delta:
        expire= datetime.utcnow()+ expires_delta
    else:
        expire= datetime.utcnow()+timedelta(minutes=30)
    
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password:str,hashed_password:str):
    decoded= cryptocode.decrypt(hashed_password,"4")
    return decoded== plain_password

def get_user_from_db(user_id:int):
    try:
        connection=get_connect()
        conn=connection.cursor(dictionary=True)
        conn.execute("select * from user where user_id=%s",(user_id,))
        user= conn.fetchone()
        return user
    except Exception as err:
        logger.error(f"Error occurred: {str(err)}")
        raise HTTPException(status_code=500, detail="error occured")
    finally:
        conn.close()
        connection.close()

def get_current_user(token:str=Depends(auth_scheme)):
    exception= HTTPException(status_code=401,detail="invalid credentials",headers={"WWW-Authenticate":"Bearer"})
    try:
        payload= jwt.decode(token, SECRET_KEY,algorithms=[ALGORITHM])
        user_id:int= payload.get("user_id")
        role:str= payload.get("role")
        if user_id is None:
            raise exception
        return TokenData(user_id= user_id,role=role)
    except JWTError:
        raise exception

@app.post("/token")
async def login_for_access_token(form_data:OAuth2PasswordRequestForm=Depends()):
    user=get_user_from_db(form_data.username)
    if not user or not verify_password(form_data.password,user["hash_password"]):
        raise HTTPException(status_code=401,detail="invalid credentials")
    
    access_token_expires=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token= create_access_token(data={"user_id":user["user_id"],"role":user["role"]},expires_delta=access_token_expires)
    return {"access_token":access_token,"bearer_type":"bearer"}

@app.get("/")
def intro():
    return "Welcome to asset management. Go to /docs."

@app.post("/upload-csv/")
async def upload_csv(file: UploadFile = File(...),current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403,detail="only admin can do this")
    
    dict_list = []
    contents = await file.read()  
    file_str = contents.decode("utf-8")  
    csv_file = StringIO(file_str)
    csv_reader = csv.reader(csv_file,delimiter=";")

    for row in csv_reader:
        if len(row) == 6:
            dict_list.append({"asset_id": row[0],"asset_name": row[1],
                "user_id": row[2],"username": row[3],
                "asset_condition": row[4],"asset_location": row[5]
            })
        else:
            print(f"Skipping malformed row: {row}")

    connection = get_connect()  
    conn = connection.cursor()
    
    for item in dict_list:
        query = "insert into asset (asset_id, asset_name, user_id, username, asset_condition, asset_location) values (%s, %s, %s, %s, %s, %s)"
        values = (item["asset_id"],item["asset_name"],item["user_id"],item["username"],item["asset_condition"],item["asset_location"])
        conn.execute(query, values)
    
    connection.commit()
    conn.close()
    connection.close()

@app.get("/user")
def get_all_users(current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403, detail="Only admin can access")
    
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary= True)
        conn.execute("select * from user;")
        result = conn.fetchall()

    except Exception as e:
        raise HTTPException(status_code=500, detail="error occured")

    finally:
        conn.close()
        connection.close()
    return result

@app.get("/asset",response_model=List[Asset])
def get_all_assets(current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403, detail= "Only admin can access")
    
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from asset;")
        result= conn.fetchall()

    except Exception as err:
        raise HTTPException(status_code=500, detail="error occured")

    finally:
        conn.close()
        connection.close()

    return result

@app.get("/user-and-asset-detail")
async def get_user_and_asset(current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise  HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection= get_connect()
        conn=connection.cursor(dictionary=True)
        conn.execute("select u.user_id,u.username,a.asset_id,a.asset_name,a.asset_condition,a.asset_location from user u join asset a on u.user_id=a.user_id")
        result= conn.fetchall()
        return result
    
    except Exception as err:
        raise HTTPException(status_code=500,detail="error occured")

    finally:
        conn.close()
        connection.close()

@app.get("/user-asset-detail/{user_id}")
async def get_your_details(user_id:int,current_user: TokenData=Depends(get_current_user)):
    print(f"Current user ID: {current_user.user_id}")
    if current_user.role=="admin" or current_user.user_id == user_id:
        try:
            connection = get_connect()
            conn=connection.cursor(dictionary=True)
            conn.execute("select u.user_id,u.username,a.asset_id,a.asset_name,a.asset_condition,a.asset_location from user u join asset a on u.user_id=a.user_id where u.user_id=%s",(user_id,))
            result= conn.fetchone()

            if not result:
                raise HTTPException(status_code=404, detail="user not found")
            return result

        except Exception as err:
            raise HTTPException(status_code=500, detail="there occured an error!")
        finally:
            conn.close()
            connection.close()
    else:
        raise HTTPException(status_code=403,detail="only authorised users can access")        

@app.post("/create-user")
async def create_user(user:User,current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary= True)
        conn.execute("insert into user values(%s,%s,%s,%s,%s)",(user.user_id,user.username,user.asset_id,user.hash_password,user.role))
        connection.commit()
        user_disp= conn.lastrowid
        return {**user.dict(),"user_id":user.user_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail="error occured")

    finally:
        conn.close()
        connection.close()

@app.post("/create-asset")
async def create_asset(asset:Asset,current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection= get_connect()
        conn=connection.cursor(dictionary= True)
        conn.execute("insert into asset values(%s,%s,%s,%s,%s,%s)",(asset.asset_id,asset.asset_name,asset.user_id,asset.username,asset.asset_condition,asset.asset_location))
        connection.commit()
        asset_disp=conn.lastrowid
        return {**asset.dict(),"asset_id":asset.asset_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail="error occured")

    finally:
        conn.close()
        connection.close()
    
@app.put("/user-update",response_model=User)
async def update_user(user_id:int,user:User,current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from user where user_id=%s",(user_id,))
        existing_user= conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code=404, detail="user not found")

        conn.execute("update user set username=%s,hash_password=%s,role=%s where user_id=%s",(user.username,user.hash_password,user.role,user_id))
        connection.commit()
        return {**user.dict(),"user_id":user_id}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="error occured")

    finally:
        conn.close()
        connection.close()

@app.put("/asset-update",response_model=Asset)
async def update_asset(asset_id:str, asset:Asset,current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection=get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from asset where asset_id=%s",(asset_id,))
        existing_user= conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code=404,detail="asset not found")
        conn.execute("update asset set asset_condition=%s,asset_location=%s where asset_id=%s" ,(asset.asset_condition,asset.asset_location,asset_id))
        connection.commit()
        return {**asset.dict(),"asset_id":asset_id}

    except Exception as err:
        raise HTTPException(status_code=500,detail="error occurred")

    finally:
        conn.close()
        connection.close()

@app.delete("/user-delete/{user_id}")
async def delete_user(user_id:int,current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary= True)
        conn.execute("select * from user where user_id=%s",(user_id,))
        existing_user= conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code=404, detail="user not found")

        conn.execute("delete from user where user_id=%s",(user_id,))
        connection.commit
        return "user deleted"

    except Exception as e:
        raise HTTPException(status_code=500, detail="error occured")

    finally:
        conn.close()
        connection.close()

@app.delete("/asset-delete/{asset_id}")
async def delete_asset(asset_id:str, current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection=get_connect()
        conn=connection.cursor(dictionary=True)
        conn.execute("select * from asset where asset_id=%s",(asset_id,))
        existing_user= conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code=404, detail="user not found")

        conn.execute("delete from asset where asset_id=%s",(asset_id,))
        connection.commit()
        return "user deleted"

    except Exception as err:
        raise HTTPException(status_code=500, detail="error occured")
    
    finally:
        conn.close()
        connection.close()
