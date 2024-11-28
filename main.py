from fastapi import FastAPI, HTTPException,Depends
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from pydantic import BaseModel
import mysql.connector
import logging
from passlib.context import CryptContext
from typing import Optional
from datetime import datetime,timedelta
from jose import JWTError,jwt

logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO)

userdb = {
    "prawin": {
        "username": "prawin",
        "hash_pwd": "$2b$12$g3yZASnK2E.jboZSrIfm1.lxEI4GV/DwhqVjKWdHwz6Bvu4DvreG.",  #prawin
        "disabled": False,
    }
}

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 450

def get_connect():
    connection= mysql.connector.connect(
        host="localhost",
        port="3307",
        user="root",
        password="root",
        database="sample"
    )
    return connection


app=FastAPI()
auth_scheme=OAuth2PasswordBearer(tokenUrl="token")
pwd_context= CryptContext(schemes=["bcrypt"],deprecated="auto")

@app.get("/")
def intro():
    return "Welcome to Asset Management. Now go to /docs."

class User(BaseModel):
    uid:int
    uname: str
    aid: int

class Asset(BaseModel):
    aid: int
    aname: str
    uid: int

class Token(BaseModel):
    access_token: str
    bearer_type: str

class Userdb(BaseModel):
    username:str
    disabled: Optional[bool]=None

class TokenData(BaseModel):
    username:str

def verify_pwd(pwd:str,hash_pwd:str):
    return pwd_context.verify(pwd,hash_pwd)

def get_admin(db,username:str):
    if username in db:
        return db[username]
    return None

def auth_user(db,username,pwd:str):
    user=get_admin(db,username)
    if not user:
        return False
    if not verify_pwd(pwd,user["hash_pwd"]):
        return False
    return user

async def create_access_token(data:dict, expires_delta:Optional[timedelta]=None):
    to_enc= data.copy()
    if expires_delta:
        expire=datetime.utcnow()+expires_delta
    else:    
        expire=datetime.utcnow()+timedelta(minutes=450)

    to_enc.update({"exp":expire})
    enc_jwt=jwt.encode(to_enc, SECRET_KEY,algorithm=ALGORITHM)
    return enc_jwt

async def get_current_user(token:str= Depends(auth_scheme)):
    cred_exp=HTTPException(status_code=401,detail="could not validate credentials",headers={"WWW-Authenticate":"Bearer"})
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username= payload.get("sub")
        if username is None:
            raise cred_exp
        return TokenData(username=username)
    except JWTError:
        raise cred_exp
    
async def get_current_active_user(current_user:TokenData=Depends(get_current_user)):
    user= get_admin(userdb, current_user.username)
    if user is None or user.get("disabled"):
        raise HTTPException(status_code=400,detail="inactive user")
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = auth_user(userdb, form_data.username,form_data.password)
    if not user or not verify_pwd(form_data.password, user["hash_pwd"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(data={"sub": user["username"]}, expires_delta=access_token_expires)  # Await the coroutine here
    return {"access_token": access_token, "bearer_type": "bearer"}


@app.get("/token-check")
async def check(current_user:TokenData= Depends(get_current_active_user)):
    return "If it is running, then it is good"

@app.post("/user-create", response_model=User)
async def create_user(user: User,current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary=True)
        conn.execute("insert into user (uid, uname, aid) values (%s, %s, %s)", 
                     (user.uid, user.uname, user.aid))
        connection.commit()
        user_disp = conn.lastrowid
        return {**user.dict(), "uid": user.uid}
    except Exception as e:
        logger.error(f"Error creating user: {e}")  
        raise HTTPException(status_code=500, detail=f"Error occurred while creating user: {str(e)}")
    finally:
        conn.close()
        connection.close()

@app.post("/asset-create",response_model=Asset)
async def create_asset(asset:Asset,current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("insert into asset values (%s,%s,%s)",(asset.aid,asset.aname,asset.uid))
        connection.commit()
        asset_disp= conn.lastrowid
        return {**asset.dict(),"uid":asset.uid}
    except Exception as e:
        logger.error(f"Error creating user: {e}")  
        raise HTTPException(status_code=500, detail=f"Error occurred while creating user: {str(e)}")
    finally:
        conn.close()
        connection.close()

@app.get("/user")
async def all_users(current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from user;")
        result= conn.fetchall()

    except Exception as e:
        raise HTTPException(status_code=500, detail="Error occured")
    finally:
        conn.close()
        connection.close()
    return result

@app.get("/asset")
async def all_asset(current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from asset;")
        result= conn.fetchall()

    except Exception as e:
        raise HTTPException(status_code=500, detail="Error occured")
    finally:
        conn.close()
        connection.close()
    return result

@app.get("/user-asset")
async def get_user_asset(current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary=True)
        query = "select u.uid, u.uname, a.aid, a.aname from user u join asset a on u.uid = a.uid"
        conn.execute(query)
        result = conn.fetchall()
        return result
    except Exception as e:
        logger.error(f"error fetching user assets: {e}")
        raise HTTPException(status_code=500, detail="error occurred while fetching user assets")
    finally:
        conn.close()
        connection.close()

@app.get("/user-asset/{uid}")
async def get_user_asset_by_uid(uid: int,current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary=True)
        query = "select u.uid, u.uname, a.aid, a.aname from user u join asset a on u.uid = a.uid where u.uid = %s"
        conn.execute(query, (uid,))
        result = conn.fetchall()
        if not result:
            raise HTTPException(status_code=404, detail="User not found with the provided uid")
        return result
    except Exception as e:
        logger.error(f"error fetching user assets by uid: {e}")
        raise HTTPException(status_code=500, detail="error occurred while fetching user assets by uid")
    finally:
        conn.close()
        connection.close()

@app.get("/user-by-asset/{aid}")
async def get_user_by_aid(aid: int,current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary=True)
        query = "select u.uid, u.uname, a.aid, a.aname from user u join asset a on u.uid = a.uid where a.aid = %s"
        conn.execute(query, (aid,))
        result = conn.fetchall()
        if not result:
            raise HTTPException(status_code=404, detail="Asset not found with the provided aid")
        return result
    except Exception as e:
        logger.error(f"error fetching user by asset: {e}")
        raise HTTPException(status_code=500, detail="error occurred while fetching user by asset")
    finally:
        conn.close()
        connection.close()

@app.put("/user-update", response_model=User)
async def update_user(uid: int, user: User,current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary=True)
        conn.execute("select * from user where uid=%s", (uid,))
        existing_user = conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code=404, detail="User not found")

        conn.execute("update user set uname=%s, aid=%s where uid=%s", (user.uname, user.aid, uid))
        connection.commit()
        return {**user.dict(), "uid": uid}
    except Exception as e:
        logger.error(f"error updating user with uid {uid}: {e}")
        raise HTTPException(status_code=500, detail="error occurred while updating user")
    finally:
        conn.close()
        connection.close()

@app.put("/asset-update", response_model=Asset)
async def update_asset(aid: int, asset: Asset,current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary=True)
        conn.execute("select * from asset where aid=%s", (aid,))
        existing_asset = conn.fetchone()

        if not existing_asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        conn.execute("update asset set aname=%s, uid=%s where aid=%s", (asset.aname, asset.uid, aid))
        connection.commit()
        return {**asset.dict(), "aid": aid}
    except Exception as e:
        logger.error(f"error updating asset with aid {aid}: {e}")
        raise HTTPException(status_code=500, detail="Error occurred while updating asset")
    finally:
        conn.close()
        connection.close()

@app.delete("/user-delete/{uid}")
async def delete_user(uid:int,current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection= get_connect()
        conn =connection.cursor(dictionary=True)
        conn.execute("select * from user where uid=%s",(uid))
        existing_user= conn.fetchone()

        if not existing_user:
            raise HTTPException(status_code=404, detail="User not found")
        conn.execute("delete from user where id=%s",(uid,))
        connection.commit()
        return "user deleted"
    except Exception as e:
        raise HTTPException(status_code=500, detail="unknown erroroccured")
    finally:
        conn.close()
        connection.close()

@app.delete("/asset-delete/{aid}")
async def delete_asset(aid:int,current_user:TokenData=Depends(get_current_active_user)):
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("select * from asset where aid=%s",(aid,))
        result=conn.fetchone()
    except Exception as e:
        raise HTTPException(status_code=500, details="error occured")
    finally:
        conn.close()
        connection.close()
