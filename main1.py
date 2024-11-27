from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import mysql.connector
import logging

logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO)



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

@app.get("/")
def intro():
    return "Welcome to Asset Management"

class User(BaseModel):
    uid:int
    uname: str
    aid: int

class Asset(BaseModel):
    aid: int
    aname: str
    uid: int

@app.post("/user/create", response_model=User)
async def create_user(user: User):
    try:
        connection = get_connect()
        conn = connection.cursor(dictionary=True)
        conn.execute("insert into user (uid, uname, aid) values (%s, %s, %s)", 
                     (user.uid, user.uname, user.aid))
        connection.commit()
        user_disp = conn.lastrowid
        return {**user.dict(), "uid": user.uid}
    except Exception as e:
        logger.error(f"Error creating user: {e}")  # Corrected typo here
        raise HTTPException(status_code=500, detail=f"Error occurred while creating user: {str(e)}")
    finally:
        conn.close()
        connection.close()

@app.post("/asset/create",response_model=Asset)
async def create_asset(asset:Asset):
    try:
        connection= get_connect()
        conn= connection.cursor(dictionary=True)
        conn.execute("insert into asset values (%s,%s,%s)",(asset.aid,asset.aname,asset.uid))
        connection.commit()
        asset_disp= conn.lastrowid
        return {**asset.dict(),"uid":asset.uid}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error occured")
    finally:
        conn.close()
        connection.close()

@app.get("/user-assets")
async def get_user_assets():
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

@app.get("/user-assets/{uid}")
async def get_user_assets_by_uid(uid: int):
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
async def get_user_by_aid(aid: int):
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
