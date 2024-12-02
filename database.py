import mysql.connector
def get_connect():
    connection = mysql.connector.connect(
        host="localhost",
        port="3307",
        user="root",
        password="root",
        database="sample"
    )
    return connection
