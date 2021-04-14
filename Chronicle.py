from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pymongo import MongoClient
import hashlib
import base64
import sys
import os


cluster = MongoClient("MongoDB Connection String")
db = cluster['DB Name'] #Database to be used
LoginCollection = db["Collection Name"] # Create a collection called 'login'

class Store():
    def padding(self,data):
            while len(data) % 16 != 0:
                data = data + " "
            return data
    backend = default_backend()
    iv = b'\xc62\xb3\x8d\x94z(\xb2\xbc\x13^\x18\r.\x92\xa7'
    key = b""

class Security():
    def decrypt(self,inp):
        paa = inp.encode()
        b64 = base64.b64decode(paa)
        cipher = Cipher(algorithms.AES(Store.key), modes.CBC(Store.iv), backend=Store.backend)
        decryptor = cipher.decryptor()
        dec = decryptor.update(b64) + decryptor.finalize()
        return dec.rstrip().decode()

    def encrypt(self,inp):
        padded_msg = Store().padding(inp).encode()
        cipher = Cipher(algorithms.AES(Store.key), modes.CBC(Store.iv), backend=Store.backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_msg) + encryptor.finalize()
        b64 = base64.b64encode(ct).decode()
        return b64

def RegisterUser():
    name = input("\nEnter your name >> ")
    email = input("Enter your email >> ")
    password = input("Enter your password >> ").encode()
    hashed = hashlib.sha256(password).hexdigest()
    LoginCollection.insert_one({"Name" : name, "eMail": email, "PasswordHash": hashed})
    print("\nSign Up Successfully Done")
    db.create_collection(email.replace('.', "_"))
    PvtCollection = db[email.replace('.','_')]
    PvtCollection.insert_one({"Identify" : "SEC_KEY","SEC_KEY": base64.b64encode(os.urandom(32)).decode()})


def LoginUser(email, password):
    state = False
    hashed = hashlib.sha256(password.encode()).hexdigest()

    ObjID = LoginCollection.find_one({"eMail" : email})['_id']
    HASH = LoginCollection.find_one({"_id" : ObjID})['PasswordHash']
    
    if HASH == hashed:
        state = True

    else:
        state = False

    return state

choice = input("\nDo you want to sign [I]n or sign [U]p ? >> ")
if choice == "I" or choice == "i":
    email = input("\nEnter the email ID >> ")
    password = input("Enter the Password >> ")
    state = LoginUser(email, password)

    if state == True:
        PvtCollection = db[email.replace('.','_')]

        ObjID = PvtCollection.find_one({"Identify" : "SEC_KEY"})['_id']
        KEYGET = PvtCollection.find_one({"_id" : ObjID})["SEC_KEY"].encode()
        KEY = base64.b64decode(KEYGET)
        Store.key = KEY

        cc = int(input("Do you want to [1]Retrieve Data or [2]Store Data >> "))
        if cc == 2:
            use = input("\nName the Collection of data >> ")
            data = input("Enter the Data to be Stored >> ")

            encrypted = Security().encrypt(data)
            PvtCollection.insert_one({"Method" : "Store","Purpose_of_Use" : use, "EncryptedData" : encrypted})

        elif cc == 1:
            data = PvtCollection.find({"Method" : "Store"})
            print("Choose the collection:- \n")
            
            for dat in data:
                print(dat["Purpose_of_Use"])
            
            purpose = input("\nEnter the collection >> ")
            ObjID = PvtCollection.find_one({"Purpose_of_Use" : purpose})['_id']
            Data = Security().decrypt(PvtCollection.find_one({"_id" : ObjID})["EncryptedData"])
            print(f"\n[DATA FOUND] --> \n{Data}")


elif choice == "U" or choice == "u":
    RegisterUser()

else:
    print("INVALID CHOICE!")
