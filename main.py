from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
import csv
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import pandas as pd
from jose import JWTError,jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import cryptocode
from io import StringIO
from datetime import datetime,timedelta
import logging
import cryptocode
import mysql.connector
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from starlette.requests import Request
from starlette.responses import JSONResponse
import os
from database import get_connect
import random
import string

#BASE MODELS FOR DATA VALIDATION
class Asset(BaseModel):
    asset_id: str  
    asset_name: str
    user_id: int
    username: str
    asset_condition: str
    asset_location: str

class UpdateAsset(BaseModel):
    asset_id: str
    user_id: Optional[int]
    asset_name: Optional[str]
    asset_location: Optional[str]

class User(BaseModel):
    user_id: int
    username: str
    hash_password: str
    role: str
    email: str

class NewUser(BaseModel):
    username: str
    password: str
    email: str

class UpdateUser(BaseModel):
    user_id: int
    username: str
    email: Optional[str] = None
    role: Optional[str] = None

class Token(BaseModel):
    access_token: str
    bearer_type: Optional[str]= None
    token_expiry_time: Optional[str]= None

class TokenData(BaseModel):
    email:str
    role:str
    user_id: Optional[str] = None

class TokenRequest(BaseModel):
    token: str

class Email(BaseModel):
    email: List[EmailStr]

#mail initialisation
conf= ConnectionConfig(
    MAIL_USERNAME="csesecondyr2257@gmail.com",
    MAIL_PASSWORD="yourpasswordisincorrect",
    MAIL_FROM="csesecondyr2257@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_FROM_NAME="SAMPLE",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)
#FastAPI and OAuth intialisation
app = FastAPI()
auth_scheme= OAuth2PasswordBearer(tokenUrl="token")

#LOGGER INITIALISATION
logger = logging.getLogger("uvicorn")
logger.setLevel(logging.ERROR)

#JWT requirements
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 450

#variables used for forgot password
token = ""
token_expiry = 0

#the security_code is an encrypted surname
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

#compares password and hashed_password
def verify_password(plain_password:str,hashed_password:str):
    decoded= cryptocode.decrypt(hashed_password,"4")
    return decoded== plain_password

#getting user from database
def get_user_from_db(email:str):
    try:
        connection=get_connect()
        conn=connection.cursor(dictionary=True)
        conn.execute("select * from user u join role r on u.user_id = r.user_id where u.email=%s",(email,))
        user= conn.fetchone()
        conn.close()
        connection.close()
        return user
    
    except Exception as err:
        logger.error(f"Error occurred: {str(err)}")
        raise HTTPException(status_code = 500, detail = "error occured")
    
#getting user details by their mail id
def get_user_by_email(email:str):
    connection = get_connect()
    conn = connection.cursor(dictionary = True)
    conn.execute("select * from user where email= %s",(email,))
    user = conn.fetchone()
        
    if not user:
        raise HTTPException(status_code=500, detail = "only users can access")

    mail = user["email"]
    if mail!= email:
        raise HTTPException(status_code = 400, detail = "invalid mail")
    return mail

#sends the mail
async def send_mail(user:User,email:str):
    mail= get_user_by_email(email)
    user= get_user_from_db(email)
    verification_token= create_access_token(data={"user_id":user["user_id"],"email":user["email"]},expires_delta=15)
    html="""<p> Hi, This is your verification token {verification_token}. This will be valid for 15 minutes only</p>"""
    message= MessageSchema(
        subject="Fastapi- Mail module",
        recipients=[email],
        body= html,
        subtype= MessageType.html
    )
    fm = FastMail(conf)
    await fm.send_message(message)
    token = verification_token
    token_expiry = datetime.utcnow() +timedelta(minutes=15)
    return {"message":"verification token has been sent to the registered mail."}
    
#gets current user and their role
def get_current_user(token:str = Depends(auth_scheme)):    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email:str = payload.get("email")
        role:str = payload.get("role")
        user_id:int = payload.get("user_id")
        hash_password: str = payload.get("hash_password")
        
        if email is None or role is None:
            raise HTTPException(status_code = 401, detail = "Credentials not enough")
        return TokenData(email = email, role = role)
    
    except JWTError as err:
        logger.error(f"Error occurred: {str(err)}")
        raise HTTPException(status_code = 401,detail = "Invalid credentials")
    

#home page
@app.get("/")
def intro():
    return "Welcome to asset management. Go to /docs."

#route for creation of token 
@app.post("/token")
async def login_for_access_token(form_data:OAuth2PasswordRequestForm=Depends()):
    user = get_user_from_db(form_data.username)
    if not user or not verify_password(form_data.password, user["hash_password"]):
        raise HTTPException(status_code = 401, detail = "invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    time = access_token_expires + datetime.utcnow()
    access_token= create_access_token(data={"email":user["email"], "role":user["role"], "user_id":user["user_id"]}, expires_delta = access_token_expires)
    return {"access_token":access_token, "bearer_type":"bearer", "token_expiry_time":time, "role":user["role"]}

#route for validating tokens
@app.post("/validate-token")
async def validate_token(request:TokenRequest ,current_user:TokenData = Depends(get_current_user)):
    token = request.token
    try:
        payload=jwt.decode(token, SECRET_KEY,algorithms=[ALGORITHM])
        mail = payload.get("email")
        user_id = payload.get("user_id")
        role =  payload.get("role")

        if current_user.email != mail:
            raise HTTPException(status_code = 401, detail = "Invalid email")
        
        expiry = payload.get("exp")
        time = datetime.utcfromtimestamp(expiry)
        if expiry and datetime.utcfromtimestamp(expiry) < datetime.utcnow():
            raise HTTPException(status_code = 401, detail = "Token expired")
        return {"message":"Access token is validated", "email":mail, "user_id":user_id, "expiry":time, "role": role}
        
    except JWTError as err:
        logger.error(f"JWT error occured: {str(err)}")
        raise HTTPException(status_code = 401, detail = "Invalid token")
    
    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")
        raise HTTPException(status_code = 500, detail = "Internal server error")

#user asset details accessible by user and admin
@app.get("/user-asset-detail/{user_id}")
async def get_your_details(user_id:int, current_user: TokenData=Depends(get_current_user)):
    print(f"Current user ID: {current_user.user_id}")

    if current_user.role=="admin" or current_user.user_id == user_id:
        try:
            connection = get_connect()
            conn = connection.cursor(dictionary=True)
            conn.execute("select u.user_id, u.username, a.asset_id, a.asset_name, a.asset_condition, a.asset_location from user u join asset a on u.user_id = a.user_id where u.user_id = %s", (user_id,))
            result = conn.fetchall()
            user_details = {}
            for entry in result:
                user_id = entry["user_id"]
                asset_id = entry["asset_id"]
                if user_id not in user_details:
                    user_details[user_id]={
                        "user_id":user_id,
                        "username":entry["username"],
                        "assets":[]
                    }
                asset_details = {
                    "asset_id":asset_id,
                    "asset_name": entry["asset_name"],
                    "asset_condition": entry[ "asset_condition"],
                    "asset_location": entry["asset_location"]
                }
                user_details[user_id]["assets"].append(asset_details)

            conn.close()
            connection.close()

            if not result:
                raise HTTPException(status_code = 404, details = "user not found")

            return user_details[user_id]

        except Exception as err:
            print(logger.error(f"Error occurred: {str(err)}"))
    else:
        raise HTTPException(status_code=403,detail="only authorised users can access")  

class ResetPassword(BaseModel):
    email: str
    new_password: str

#reset password done by authorised user and admin
@app.post("/reset-password")
async def reset_password(request: ResetPassword, current_user: TokenData=Depends(get_current_user)):
    if current_user.role == "admin" or current_user.email == request.email:
        print("current_user", current_user.email, current_user.role)
        try:
            connection = get_connect()
            conn = connection.cursor(dictionary=True)
            conn.execute("select * from user where email=%s",(request.email,))
            existing_user = conn.fetchone()

            if not existing_user:
                raise HTTPException(status_code=404, detail="user not found")
            hash_password=create_password(request.new_password)
            conn.execute("update user set hash_password= %s where email= %s", (hash_password, request.email))
            connection.commit()
            conn.close()
            connection.close()
            return {"message": "Password changed"}

        except Exception as err:
            logger.error(f"Error occurred: {str(err)}")
            raise HTTPException(status_code=500, detail="error occured")
        

#uploading asset csv can only be done by admin
@app.post("/upload-csv-asset/")
async def upload_csv_for_asset(file: UploadFile = File(...), current_user: TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code = 403, detail = "Only admins can perform this operation.")
    
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
            asset_condition = row[4]
            asset_location = row[5]
            
            if not isinstance(asset_id, str) or not isinstance(asset_name, str) or not isinstance(asset_condition, str) or not isinstance(asset_location, str):
                raise HTTPException(status_code=400, detail=f"asset_id '{asset_id}',asset_name, username, asset_condition and asset_location must be strings.")

            try:
                user_id = int(user_id)
            except ValueError as err:
                logger.error(f"Error occurred: {str(err)}")
                raise HTTPException(status_code=400, detail=f"Invalid user_id '{user_id}' in CSV file. user_id must be an integer.")
            
            dict_list.append({
                "asset_id": asset_id, "asset_name": asset_name, "user_id": user_id,
                "asset_condition": asset_condition, "asset_location": asset_location
            })
        else:
            print(f"Skipping malformed row: {row}")
    
    connection = get_connect()
    conn = connection.cursor()

    for item in dict_list:
        query = "insert into asset values (%s, %s, %s, %s, %s)"
        values = (item["asset_id"], item["asset_name"], item["user_id"], item["asset_condition"], item["asset_location"])
        conn.execute(query, values)

    connection.commit()
    conn.close()
    connection.close()

#uploading user csv can only be done by admin
@app.post("/upload-csv-user/")
async def upload_csv_for_user(file:UploadFile=File(...),current_user: TokenData=Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code = 403, detail= "Only admins can do this")
    
    dict_list=[]
    contents = await file.read()
    file_str = contents.decode("utf-8")
    csv_file = StringIO(file_str)
    csv_reader = csv.reader(csv_file, delimiter=";")

    for row in csv_reader:
        if len(row) == 5:
            user_id = row[0]
            username = row[1]
            hash_password = row[2]
            role = row[3]
            email = row[4]

            if not isinstance(username,str) or not isinstance(hash_password,str) or not isinstance(role, str) or not isinstance(email, str):
                raise HTTPException(status_code=400, detail="username, hash_password, role must be strings")
            
            try:
                user_id = int(user_id)
            except ValueError as e:
                logger.error(f"Error occurred: {str(e)}")
                raise HTTPException(status_code= 400, detail=f"user_id '{user_id}' must be an integer")
            
            hash_password=create_password(hash_password)
            dict_list.append({
                "user_id":user_id, "username":username,
                "hash_password":create_password(hash_password),
                "role":role, "email":email
            })
        else:
            print(f"Skipping malformed row:'{row}'")

        connection= get_connect()
        conn= connection.cursor()

        for item in dict_list:
            query= "insert into user values(%s, %s, %s, %s, %s)"
            value= (item["user_id"], item["username"], item["hash_password"], item["role"], item["email"])
            conn.execute(query, value)
        
        connection.commit()
        conn.close()
        connection.close()

#details of every user only accesible by admin
@app.get("/user")
def get_all_users(current_user:TokenData = Depends(get_current_user)):
    print("current_user", current_user.email, current_user.role)
    if current_user.role != "admin":
        raise HTTPException(status_code = 403, detail = "Only admin can access")
    
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary= True)
        conn.execute("select * from user;")
        result = conn.fetchall()
        conn.close()
        connection.close()

    except Exception as err:
        logger.error(f"Error occurred: {str(err)}")
        raise HTTPException(status_code = 500, detail = "error occured")

    return result

#admin can see all asset details
@app.get("/asset")
def get_all_assets(current_user:TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code = 403, detail = "Only admin can access")
    
    try:
        connection= get_connect()
        conn = connection.cursor(dictionary=True)
        conn.execute("select * from asset;")
        result = conn.fetchall()
        user_details = {}
        for entry in result:
            user_id = entry["user_id"]
            if user_id not in user_details:
                user_details[user_id] = {
                    "user_id": user_id,
                    "assets":[]
                }
            asset_details = {
                    "asset_id": entry['asset_id'],
                    "asset_name": entry["asset_name"],
                    "asset_condition": entry["asset_condition"],
                    "asset_location": entry["asset_location"]
            }
            user_details[user_id]["assets"].append(asset_details)

        conn.close()
        connection.close()

    except Exception as err:
        raise HTTPException(status_code=500, detail="error occured")

    return user_details

#only admin can see user and asset details combined
@app.get("/user-and-asset-detail")
async def get_user_and_asset(current_user:TokenData=Depends(get_current_user)):
    if current_user.role!="admin":
        raise  HTTPException(status_code=403,detail="only admin can access")
    
    try:
        connection= get_connect()
        conn=connection.cursor(dictionary=True)
        conn.execute("select u.user_id, u.username, a.asset_id, a.asset_name, a.asset_condition, a.asset_location from user u join asset a on u.user_id = a.user_id")
        result= conn.fetchall()
        user_details={}
        for entry in result:
            user_id = entry["user_id"]
            if user_id not in user_details:
                user_details[user_id] = {
                    "user_id": user_id,
                    "username": entry["username"],
                    "assets": []
                }
            asset_details = {
                "asset_id": entry["asset_id"],
                "asset_name": entry["asset_name"],
                "asset_condition": entry["asset_condition"],
                "asset_location":entry["asset_location"]
            }
            user_details[user_id]["assets"].append(asset_details)
        conn.close()
        connection.close()
    
    except Exception as err:
        raise HTTPException(status_code=500,detail="error occured")
    
    return user_details
    
#creating users can be only done by admin
@app.post("/create-user")
async def create_user(user:User, current_user:TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code = 403,detail = "only admin can access")
    
    user.hash_password = create_password(user.hash_password)

    try:
        connection= get_connect()
        conn= connection.cursor(dictionary = True)
        conn.execute("insert into user values(%s, %s, %s, %s)",(user.username,user.hash_password,user.role,user.email))
        connection.commit()
        conn.close()
        connection.close()
        return {"message":"user created"}

    except Exception as e:
        raise HTTPException(status_code = 500, detail = "error occured")

#creating asset can only be done by admin
@app.post("/create-asset")
async def create_asset(asset:Asset,current_user:TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code = 403,detail = "only admin can access")
    
    try:
        connection= get_connect()
        conn=connection.cursor(dictionary = True)
        conn.execute("insert into asset values(%s, %s, %s, %s, %s)",(asset.asset_id, asset.asset_name, asset.user_id, asset.asset_condition, asset.asset_location))
        connection.commit()
        conn.close()
        connection.close()
        return {"message":"asset created"}

    except Exception as e:
        (print(f"Error occurred: {str(e)}"))
        raise HTTPException(status_code = 500, detail = "an error occured")

#updating user details can only be done by admin
@app.put("/user-update", response_model = UpdateUser)
async def update_user(user:UpdateUser, current_user:TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code = 403,detail = "only admin can access")
    
    try:
        connection=get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from user where user_id = %s",( user.user_id,))
        existing_user = conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code=404,detail="user not found")
        conn.execute("update user set username = %s,email = %s,role = %s where user_id = %s" ,(user.username, user.email, user.role, user.user_id))
        connection.commit()
        conn.close()
        connection.close()
        return {**user.dict(), "user_id":user.user_id}

    except Exception as err:
        raise HTTPException(status_code = 500,detail = "error occurred")
    
#updating assets can only be done by admin    
@app.put("/asset-update", response_model = UpdateAsset)
async def update_asset(asset:UpdateAsset, current_user:TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code = 403,detail = "only admin can access")
    
    try:
        connection=get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from asset where asset_id = %s", (asset.asset_id,))
        existing_user= conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code = 404,detail="asset not found")
        conn.execute("update asset set user_id = %s, asset_name = %s, asset_location = %s where asset_id= %s" ,(asset.user_id, asset.asset_name, asset.asset_location, asset.asset_id))
        connection.commit()
        conn.close()
        connection.close()
        return asset
    
    except Exception as err:
        raise HTTPException(status_code = 500,detail = "error occurred")

#user deletion can only be done by admin
@app.delete("/user-delete/")
async def delete_user(user_id:int, current_user:TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code = 403,detail = "only admin can access")
    
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary = True)
        conn.execute("select * from user where user_id = %s", (user_id,))
        existing_user = conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code = 404, detail = "user not found")

        conn.execute("delete from user where user_id = %s", (user_id,))
        connection.commit()
        conn.close()
        connection.close()
        return{"message":"user deleted"}

    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail="error occured")

    finally:
        conn.close()
        connection.close()

#asset deletion can only be done by admin
@app.delete("/asset-delete")
async def delete_asset(asset_id:str, current_user:TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code = 403, detail = "only admin can access")
    
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary=True)
        conn.execute("select * from asset where asset_id = %s", (asset_id,))
        existing_user = conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code = 404, detail = "asset not found")

        conn.execute("delete from asset where asset_id = %s", (asset_id,))
        connection.commit()
        conn.close()
        connection.close()
        return {"message":"asset deleted"}

    except Exception as err:
        print(f"Error: {err}")
        raise HTTPException(status_code = 500, detail = "error occured")

#triggers to send a mail with verification token  
@app.post("/forgot-password")
async def forgot_password(user_id:int, email:str):
    user = get_user_by_email(email)
    await send_mail(email)
    return {"message":"Go to create-new-password if you get the token."}

#after receiving verification mail, create the new password
@app.post("/create-new-password")
async def create_new_password(email:str, verification_token:str, new_password:str):
    payload = jwt.decode(token, SECRET_KEY,algorithms=[ALGORITHM])
    mail: str = payload.get("email")
    try:
        if verification_token == token and token_expiry>datetime.utcnow() and (mail == email):
            connection = get_connect()
            conn = connection.cursor(dictionary=True)
            conn.execute("select * from user where email=%s", (email,))
            existing_user = conn.fetchone()
            hash_password = create_password(new_password)
            conn.execute("update user set hash_password=%s where email=%s",(hash_password, email))
            connection.commit()
            conn.close()
            connection.close()
            logger.error(f"Error occured:{str(err)}")
            return {"message":"password changed"}
        
    except Exception as err:
        logger.error(f"Error occured:{str(err)}")
        raise HTTPException(status_code=500, detail="Error occured")

@app.post("/register-user")
async def register_user(user:NewUser):
    user.password = create_password(user.password)
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary = True)
        conn.execute("select * from user where email = %s",(user.email,))
        existing_user = conn.fetchone()
        if existing_user:
            raise HTTPException(status_code = 400, detail = "user already exists")
        
        conn.execute("insert into user(username, hash_password, email) values(%s, %s, %s)",(user.username, user.password, user.email))
        connection.commit()
        conn.close()
        connection.close()
    
    except Exception:
        raise HTTPException(status_code = 500, detail = "server error")
    
    return {"message": "registration successful"}
