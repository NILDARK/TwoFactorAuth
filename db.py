import pymongo
from creds import dbname,dbpass
import base64,hashlib

def addUser(details):
    '''
    Adds user encoded user details to database and creates user.
    rtype: boolean
    '''
    try:
        client = pymongo.MongoClient(f"mongodb://{dbname}:{dbpass}@cluster0-shard-00-00.jk81v.mongodb.net:27017,cluster0-shard-00-01.jk81v.mongodb.net:27017,cluster0-shard-00-02.jk81v.mongodb.net:27017/?ssl=true&replicaSet=atlas-rms0md-shard-0&authSource=admin&retryWrites=true&w=majority")
        db = client.get_database('userDB')
        col = db["users"]
        m = hashlib.sha256(details[2].encode())
        pswd = m.hexdigest()
        record = {"name":base64.b64encode(details[0].encode("ascii")).decode("ascii"),"username":base64.b64encode(details[1].encode("ascii")).decode("ascii"),"password":pswd,"email":base64.b64encode(details[3].encode("ascii")).decode("ascii"),"devices":{}}
        col.insert_one(record)
        return True
    except Exception as err:
        print(err)
        return False
    
def login(username):
    '''
    Logs in the user having user name 'username'
    '''
    try:
        client = pymongo.MongoClient(f"mongodb://{dbname}:{dbpass}@cluster0-shard-00-00.jk81v.mongodb.net:27017,cluster0-shard-00-01.jk81v.mongodb.net:27017,cluster0-shard-00-02.jk81v.mongodb.net:27017/?ssl=true&replicaSet=atlas-rms0md-shard-0&authSource=admin&retryWrites=true&w=majority")
        db = client.get_database('userDB')
        col = db["users"]
        query = {"username":username}
        res = col.find(query)
        for x in res:
            y = x
        return False
    except Exception as err:
        print(err)
        return False
    
def isTrustedDevice(username,mac):
    '''
    Checks if user 'username' has machine 'mac' in his trust list. If in his trust list then no Two Factor authentication is needed else there is need of two factor Auth.
    rtype: boolean
    '''
    try:
        client = pymongo.MongoClient(f"mongodb://{dbname}:{dbpass}@cluster0-shard-00-00.jk81v.mongodb.net:27017,cluster0-shard-00-01.jk81v.mongodb.net:27017,cluster0-shard-00-02.jk81v.mongodb.net:27017/?ssl=true&replicaSet=atlas-rms0md-shard-0&authSource=admin&retryWrites=true&w=majority")
        db = client.get_database('userDB')
        col = db["users"]
        query = {"username":base64.b64encode(username.encode("ascii")).decode("ascii")}
        res = col.find(query)
        for y in res:
            x = y["devices"]
        try:
            if(x[mac]==1):
                return True
            else:
                return False
        except:
            return False
    except Exception as err:
        print(err)
        return False
    
def logOut(username,status = False):
    '''
    Logs out the user 'username'.
    rtype: boolean
    '''
    try:
        client = pymongo.MongoClient(f"mongodb://{dbname}:{dbpass}@cluster0-shard-00-00.jk81v.mongodb.net:27017,cluster0-shard-00-01.jk81v.mongodb.net:27017,cluster0-shard-00-02.jk81v.mongodb.net:27017/?ssl=true&replicaSet=atlas-rms0md-shard-0&authSource=admin&retryWrites=true&w=majority")
        db = client.get_database('quiz')
        col = db["quizAdmins"]
        query = {"username":base64.b64encode(username.encode("ascii")).decode("ascii")}
        new = {"$set":{"isActive":status}}
        col.update_one(query,new)   
        return True
    except Exception as err:
        print(err)
        return False
    
def verifyUsername(username):
    '''
    Check if username exists in database, if exists then return its password hash.
    Returns array [True,hash_str] if username exist in db
    Returns array [False, None] if username does not exist in db
    rtype: array -> [boolean,str/None] 
    '''
    try:
        client = pymongo.MongoClient(f"mongodb://{dbname}:{dbpass}@cluster0-shard-00-00.jk81v.mongodb.net:27017,cluster0-shard-00-01.jk81v.mongodb.net:27017,cluster0-shard-00-02.jk81v.mongodb.net:27017/?ssl=true&replicaSet=atlas-rms0md-shard-0&authSource=admin&retryWrites=true&w=majority")
        db = client.get_database('userDB')
        col = db["users"]
        query = {"username":base64.b64encode(username.encode("ascii")).decode("ascii")}
        res = col.find(query)   
        for x in res:
            return [True,x["password"]]
        else:
            return [False,None]
    except Exception as err:
        print(err)
        return [False,None]
    
def checkEmailAvaibility(email):
    '''
    Checks if email is available to use.
    Returns True if email not already in use
    Returns False if email already in use
    rtype: boolean
    '''
    try:
        client = pymongo.MongoClient(f"mongodb://{dbname}:{dbpass}@cluster0-shard-00-00.jk81v.mongodb.net:27017,cluster0-shard-00-01.jk81v.mongodb.net:27017,cluster0-shard-00-02.jk81v.mongodb.net:27017/?ssl=true&replicaSet=atlas-rms0md-shard-0&authSource=admin&retryWrites=true&w=majority")
        db = client.get_database('userDB')
        col = db["users"]
        query = {"email":base64.b64encode(email.encode("ascii")).decode("ascii")}
        res = col.find(query)   
        for x in res:
            return False
        else:
            return True
    except Exception as err:
        print(err)
        return None
    
def addDevice(username,mac):
    '''
    Adds device having mac address 'mac' to trusted list of user 'username'.
    rtype: boolean
    '''
    try:
        client = pymongo.MongoClient(f"mongodb://{dbname}:{dbpass}@cluster0-shard-00-00.jk81v.mongodb.net:27017,cluster0-shard-00-01.jk81v.mongodb.net:27017,cluster0-shard-00-02.jk81v.mongodb.net:27017/?ssl=true&replicaSet=atlas-rms0md-shard-0&authSource=admin&retryWrites=true&w=majority")
        db = client.get_database('userDB')
        col = db["users"]
        query = {"username":base64.b64encode(username.encode("ascii")).decode("ascii")}
        res = col.find(query)
        for y in res:
            x = y["devices"]
        x[mac]= 1
        new = {"$set":{"devices":x}}
        col.update_one(query,new)   
        return True
    except Exception as err:
        print(err)
        return False
    
def updateDevice(username,mac,status=0):
    '''
    Updates device's trust value.
    rtype: boolean
    '''
    try:
        client = pymongo.MongoClient(f"mongodb://{dbname}:{dbpass}@cluster0-shard-00-00.jk81v.mongodb.net:27017,cluster0-shard-00-01.jk81v.mongodb.net:27017,cluster0-shard-00-02.jk81v.mongodb.net:27017/?ssl=true&replicaSet=atlas-rms0md-shard-0&authSource=admin&retryWrites=true&w=majority")
        db = client.get_database('userDB')
        col = db["users"]
        query = {"username":base64.b64encode(username.encode("ascii")).decode("ascii")}
        res = col.find(query)
        for y in res:
            x = y["devices"]
        x[mac]=status
        new = {"$set":{"devices":x}}
        col.update_one(query,new)   
        return True
    except Exception as err:
        print(err)
        return False
    
def getUserEmail(username):
    '''
    Get Email and Name of user 'username'.
    Returns [email,name] if username is valid else returns None
    rtype: array -> [str,str]/None
    '''
    try:
        client = pymongo.MongoClient(f"mongodb://{dbname}:{dbpass}@cluster0-shard-00-00.jk81v.mongodb.net:27017,cluster0-shard-00-01.jk81v.mongodb.net:27017,cluster0-shard-00-02.jk81v.mongodb.net:27017/?ssl=true&replicaSet=atlas-rms0md-shard-0&authSource=admin&retryWrites=true&w=majority")
        db = client.get_database('userDB')
        col = db["users"]
        query = {"username":base64.b64encode(username.encode("ascii")).decode("ascii")}
        res = col.find(query)   
        # print(res['email'])
        for x in res:
            return [base64.b64decode(x['email'].encode("ascii")).decode("ascii"),base64.b64decode(x['name'].encode("ascii")).decode("ascii")]
        return None
    except Exception as err:
        print(err)
        return None
    
if __name__=="__main__":
    pass
    