from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
import csv
from pydantic import BaseModel
from typing import List
import pandas as pd
from jose import JWTError,jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import cryptocode
from io import StringIO
from datetime import datetime,timedelta
import logging
import cryptocode
from database import get_connect

#LOGGER INITIALISATION
logger = logging.getLogger("uvicorn")
logger.setLevel(logging.ERROR)

#BASE MODELS FOR DATA VALIDATION
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
    security_code: str

class Token(BaseModel):
    access_token: str
    bearer_type: str

class TokenData(BaseModel):
    user_id:int
    role:str

#JWT requirements
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 450

app = FastAPI()
auth_scheme= OAuth2PasswordBearer(tokenUrl="token")

def last_name(username:str):
    split_name=username.split()
    last_name=split_name[-1]
    return last_name.lower()

#cryptocode password creation
def create_password(new_password:str):
    encoded= cryptocode.encrypt(new_password,"4")
    return encoded

#cryptocode password decryption
def crypt_decode(password:str):
    decoded= cryptocode.decrypt(password,"4")
    return decoded

#access token creation for authentication
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

#getting user from database
def get_user_from_db(user_id:int):
    try:
        connection=get_connect()
        conn=connection.cursor(dictionary=True)
        conn.execute("select * from user where user_id=%s",(user_id,))
        user= conn.fetchone()
        conn.close()
        connection.close()
        return user
    
    except Exception as err:
        logger.error(f"Error occurred: {str(err)}")
        raise HTTPException(status_code=500, detail="error occured")
    

#gets current user
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
        logger.error(f"Error occurred: {str(err)}")
        raise exception
    
#route for creation of token 
@app.post("/token")
async def login_for_access_token(form_data:OAuth2PasswordRequestForm=Depends()):
    user=get_user_from_db(form_data.username)
    if not user or not verify_password(form_data.password,user["hash_password"]):
        raise HTTPException(status_code=401,detail="invalid credentials")
    
    access_token_expires=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token= create_access_token(data={"user_id":user["user_id"],"role":user["role"]},expires_delta=access_token_expires)
    return {"access_token":access_token,"bearer_type":"bearer"}

#home page
@app.get("/")
def intro():
    return "Welcome to asset management. Go to /docs."

#user asset details accessible by user and admin
@app.get("/user-asset-detail/{user_id}")
async def get_your_details(user_id:int,current_user: TokenData=Depends(get_current_user)):
    print(f"Current user ID: {current_user.user_id}")

    if current_user.role=="admin" or current_user.user_id == user_id:
        try:
            connection = get_connect()
            conn=connection.cursor(dictionary=True)
            conn.execute("select u.user_id,u.username,a.asset_id,a.asset_name,a.asset_condition,a.asset_location from user u join asset a on u.user_id=a.user_id where u.user_id=%s",(user_id,))
            result= conn.fetchone()
            logger.error(f"Error occurred: {str(err)}")


            if not result:                        
                logger.error(f"Error occurred: {str(err)}")
                raise HTTPException(status_code=404, detail="user not found")
            return result

        except Exception as err:

            raise HTTPException(status_code=500, detail="there occured an error!")
        finally:
            conn.close()
            connection.close()

    else:
        raise HTTPException(status_code=403,detail="only authorised users can access")  

#forgot password can be created if you know the security_code
@app.post("/forgot-password")
def forgot_password(user_id:int,security_code:str,new_password:str):
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from user where user_id=%s",(user_id,))
        user= conn.fetchone()

        if not user:
            raise HTTPException(status_code=404,detail="user not found")
        
        username= user["username"]
        existing_code= crypt_decode(user["security_code"])

        if existing_code!=security_code:
            raise HTTPException(status_code=400, details="Invalid security")
        
        hash_password= create_password(new_password)
        conn.execute("update user set hash_password= %s where user_id= %s",(hash_password,user_id))
        connection.commit()
        conn.close()
        connection.close()

    except Exception as e:
        logger.error(f"Error occurred: {str(err)}")
        raise HTTPException(status_code=500,detail="unknown error occured")

    return {"message":"password has been reset"}

#reset password done by authorised user and admin
@app.post("/reset-password")
async def reset_password(user_id:int,new_password: str,current_user: TokenData=Depends(get_current_user)):
    if current_user.role=="admin" or current_user.user_id == user_id:
        try:
            connection=get_connect()
            conn= connection.cursor(dictionary=True)
            conn.execute("select * from user where user_id=%s",(user_id,))
            existing_user= conn.fetchone()

            if not existing_user:
                raise HTTPException(status_code=404, detail="user not found")
            hash_password=create_password(new_password)
            conn.execute("update user set hash_password=%s where user_id=%s",(hash_password,user_id))
            connection.commit()
            conn.close()
            connection.close()
            logger.error(f"Error occurred: {str(err)}")
            return {"message": "Password changed"}

        except Exception as err:
            logger.error(f"Error occurred: {str(err)}")
            raise HTTPException(status_code=500, detail="error occured")
        

#uploading asset csv can only be done by admin
@app.post("/upload-csv-asset/")
async def upload_csv_for_asset(file: UploadFile = File(...), current_user: TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can perform this operation.")
    
    dict_list = []
    contents = await file.read()
    file_str = contents.decode("utf-8")
    csv_file = StringIO(file_str)
    csv_reader = csv.reader(csv_file, delimiter=";")

    for row in csv_reader:
        if len(row) == 6:
            asset_id = row[0]
            asset_name = row[1]
            user_id = row[2]
            username = row[3]
            asset_condition = row[4]
            asset_location = row[5]
            
            if not isinstance(asset_id, str) or not isinstance(asset_name, str) or not isinstance(username, str) or not isinstance(asset_condition, str) or not isinstance(asset_location, str):
                raise HTTPException(status_code=400, detail=f"asset_id '{asset_id}',asset_name, username, asset_condition and asset_location must be strings.")

            try:
                user_id = int(user_id)
            except ValueError as err:
                logger.error(f"Error occurred: {str(err)}")
                raise HTTPException(status_code=400, detail=f"Invalid user_id '{user_id}' in CSV file. user_id must be an integer.")
            
            dict_list.append({
                "asset_id": asset_id,"asset_name": asset_name,"user_id": user_id,
                "username": username,"asset_condition": asset_condition,"asset_location": asset_location
            })
        else:
            print(f"Skipping malformed row: {row}")
    
    connection = get_connect()
    conn = connection.cursor()

    for item in dict_list:
        query = "insert into asset values (%s, %s, %s, %s, %s, %s)"
        values = (item["asset_id"], item["asset_name"], item["user_id"], item["username"],item["asset_condition"], item["asset_location"])
        conn.execute(query, values)

    connection.commit()
    conn.close()
    connection.close()

#uploading user csv can only be done by admin
@app.post("/upload-csv-user/")
async def upload_csv_for_user(file:UploadFile=File(...),current_user: TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403, detail="Only admins can do this")
    
    dict_list=[]
    contents= await file.read()
    file_str= contents.decode("utf-8")
    csv_file= StringIO(file_str)
    csv_reader= csv.reader(csv_file, delimiter=";")

    for row in csv_reader:
        if len(row)==6:
            user_id=row[0]
            username= row[1]
            asset_id= row[2]
            hash_password=row[3]
            role= row[4]
            security_code=row[5]

            if not isinstance(username,str) or not isinstance(asset_id, str) or not isinstance(hash_password,str) or not isinstance(role, str) or not isinstance(security_code, str):
                logger.error(f"Error occurred: {str(err)}")
                raise HTTPException(status_code=400, detail=f"asset_id '{asset_id}', username, hash_password,role must be strings")
            
            try:
                user_id= int(user_id)
            except ValueError:
                logger.error(f"Error occurred: {str(err)}")
                raise HTTPException(status_code= 400, detail=f"user_id '{user_id}' must be an integer")
            
            hash_password=create_password(hash_password)
            dict_list.append({
                "user_id":user_id,"username":username,
                "asset_id":asset_id,"hash_password":hash_password,
                "role":role,"security_code":security_code
            })
        else:
            print(f"Skipping malformed row:'{row}'")

        connection= get_connect()
        conn= connection.cursor()

        for item in dict_list:
            query= "insert into user values(%s,%s,%s,%s,%s,%s)"
            value= (item["user_id"],item["username"],item["asset_id"],item["hash_password"],item["role"],item["security_code"])
            conn.execute(query, value)
        
        connection.commit()
        conn.close()
        connection.close()

#details of every user only accesible by admin
@app.get("/user")
def get_all_users(current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403, detail="Only admin can access")
    
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary= True)
        conn.execute("select * from user;")
        result = conn.fetchall()
        conn.close()
        connection.close()

    except Exception as err:
        logger.error(f"Error occurred: {str(err)}")
        raise HTTPException(status_code=500, detail="error occured")

    return result

#admin can see all asset details
@app.get("/asset",response_model=List[Asset])
def get_all_assets(current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403, detail= "Only admin can access")
    
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from asset;")
        result= conn.fetchall()
        conn.close()
        connection.close()

    except Exception as err:
        raise HTTPException(status_code=500, detail="error occured")

    return result

#only admin can see user and asset details combined
@app.get("/user-and-asset-detail")
async def get_user_and_asset(current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise  HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection= get_connect()
        conn=connection.cursor(dictionary=True)
        conn.execute("select u.user_id,u.username,a.asset_id,a.asset_name,a.asset_condition,a.asset_location from user u join asset a on u.user_id=a.user_id")
        result= conn.fetchall()
        conn.close()
        connection.close()
        return result
    
    except Exception as err:
        raise HTTPException(status_code=500,detail="error occured")
    
#creating users can be only done by admin
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
        conn.close()
        connection.close()
        return {**user.dict(),"user_id":user.user_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail="error occured")

#creating asset can only be done by admin
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
        conn.close()
        connection.close()
        return {**asset.dict(),"asset_id":asset.asset_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail="error occured")

#updating user details can only be done by admin
@app.put("/user-update",response_model=User)
async def update_user(user_id:int, user:User,current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection=get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from user where user_id=%s",(user_id,))
        existing_user= conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code=404,detail="user not found")
        conn.execute("update user set user_id=%s,username=%s where asset_id=%s" ,(user.user_id,user.username,user.role))
        connection.commit()
        conn.close()
        connection.close()
        return {**user.dict(),"user_id":user_id}

    except Exception as err:
        raise HTTPException(status_code=500,detail="error occurred")
    
#updating assets can only be done by admin
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
        conn.close()
        connection.close()
        return {**asset.dict(),"asset_id":asset_id}

    except Exception as err:
        raise HTTPException(status_code=500,detail="error occurred")

#user deletion can only be done by admin
@app.delete("/user-delete/")
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
        conn.close()
        connection.close()
        connection.commit()
        return{"message":"user deleted"}

    except Exception as e:
        raise HTTPException(status_code=500, detail="error occured")

    finally:
        conn.close()
        connection.close()

#asset deletion can only be done by admin
@app.delete("/asset-delete")
async def delete_asset(asset_id:str, current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection=get_connect()
        conn=connection.cursor(dictionary=True)
        conn.execute("select * from asset where asset_id=%s",(asset_id,))
        existing_user= conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code=404, detail="asset not found")

        conn.execute("delete from asset where asset_id=%s",(asset_id,))
        connection.commit()
        conn.close()
        connection.close()
        return {"message":"asset deleted"}

    except Exception as err:
        raise HTTPException(status_code=500, detail="error occured")
    

