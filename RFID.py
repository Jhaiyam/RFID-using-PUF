import sys
import random
import uuid
import mysql.connector
Ci =0
Ri =0
random_number=100
global buffer_rfid
global buffer_server
global buffer_rfid2
global buffer_server2

def update(tid1,ci1,ri1,tag_id):#10 update database if ress = resT
    mydb = mysql.connector.connect(
          host="127.0.0.1",
          user="root",
          password="root@123",
          database="nsserver")
    mycursor = mydb.cursor()
    sql = """UPDATE serverside SET emergency_challenge = %s,emergency_response=%s,pid=%s WHERE pid = %s"""
    val = (ci1,ri1,tid1,tag_id)
    mycursor.execute(sql,val)
    mydb.commit()

def server_final_auth(tag_id,Nsclient,count,rest,response_xor1,resp,challen1,resp1,tid1):# 9
    ki = hash(resp or Nsclient)
    response_xor1 = int(response_xor1)
    rest1 = hash(count + 2 or ki or response_xor1)
    print("\nCalculated ResT or the new challenge which is to be stored in server= ",rest1-1)
    if(int(rest) == rest1):
        rest=rest-1
        resp1 = ki ^ response_xor1
        challen1 = hash(count + 2 or Nsclient or resp)
        tid1 = hash(int(tag_id) or resp1)
        update(int(tid1),int(challen1-1),int(resp1),int(tag_id))
    else:
        print("Authentication failed")
    

    
    

def rfid_calc(tag_id,count,challenge2,response2,Ress,response2_xor): #8, called from server_calc
    print("Tag id received from the server= ",challenge2)
    print("Tag id received  Ri* from the server ",response2_xor)
    print("Ress recevied from server ",Ress)
    resp = PUF(int(challenge2))
    Ress_from_client = hash(int(count) + 1 or resp or int(response2_xor))
    if(Ress_from_client == int(Ress)):
        Nsclient = resp^ int(response2_xor)
        print("Nsclient received from server= ",Nsclient)
        challen1 = hash(int(count) + 2 or Nsclient or resp)
        resp1 = PUF(challen1)
        ki = hash(resp or Nsclient)
        response_xor1 = ki ^ resp1
        rest = hash(int(count) + 2 or ki or response_xor1)
        tid1 = hash(int(tag_id) or resp1)
        g = open("rfid_buffer.txt", "a")
        g.write(str(tid1))
        g.close()
        server_final_auth(tag_id,Nsclient,count,rest,response_xor1,resp,challen1,resp1,tid1)

    else:
            print("unauthorised RFID tag")
    


def server_calc(tag_id,count,dataset): #7, called from tag auth phase
    Ns = random.randint(99,999999)
    print("ns= ",Ns)
    response2 = int(dataset[0][2])
    challenge2 = dataset[0][1]
    response2_xor = response2^ Ns
    Ress = hash(count + 1 or response2 or response2_xor)
    rfid_calc(tag_id,count,challenge2,response2,Ress,response2_xor)



    
def server_auth_phase(tag_id,count): #6
    mydb = mysql.connector.connect(
          host="127.0.0.1",
          user="root",
          password="root@123",
          database="nsserver")
    mycursor = mydb.cursor()
    sql="select *from serverside where pid="+tag_id
    mycursor.execute(sql)
    pair= mycursor.fetchall()
    s_tid = pair[0][0]
    serversidechalllenge = ""
    serversideresponse = ""

    if (int(s_tid)!=int(tag_id)):
        print("Tag ID is not same in the rfid tag and server, not authenticated")

    else:
        return pair
        
    

def tag_auth_phase():#5, called from main
    g = open("rfid_buffer.txt", "r")
    tag_id = g.readline()
    g.close()
    count=random.randint(0,1000000)
    dataset=server_auth_phase(tag_id,count)#perform server authentication for the selected tag
    server_calc(tag_id,count,dataset)
    

    
   
def message_exchange_store(tid,challenges,response,Ci,Ri): #4
    global TID
    TID=tid

    buffer_cem= []
    buffer_rem=[]
    buffer_ci=[]
    mydb = mysql.connector.connect(
          host="127.0.0.1",
          user="root",
          password="root@123",
          database="nsserver")
    mycursor = mydb.cursor()
    
    sql = "Delete from serverside"
    mycursor.execute(sql)
    mydb.commit()

    pid=[]

    for i in range (100):
        pid.append(random.randrange(i, 2**32,100))

    for i in range(100):
        buffer_cem.append(challenges[i])

    for i in range(100):
        buffer_rem.append(response[i])

    buffer_ci.append(Ci)

    
    for i in range(100):
        sql="insert into serverside (pid,emergency_challenge,emergency_response) VALUES (%s,%s,%s)"
        a=pid[i]
        b=buffer_cem[i]
        c=buffer_rem[i]
        val=(a,b,c)
        mycursor.execute(sql,val)
        mydb.commit()

    sql = "INSERT INTO serverside (pid,emergency_challenge,emergency_response) VALUES (%s,%s,%s)"
    val = (tid,Ci,Ri)
    mycursor.execute(sql, val)
    mydb.commit()
    tid=str(tid)
    a = open("rfid_buffer.txt", "w")
    a.write(tid)# write the tag id in the rfid buffer 
    a.write("\n")
    for i in range(0,100):
        a.write(str(pid[i]))# write all pid in the rfid buffer
        a.write("\n")
    a.close()

    
    

def Backend_Server(): #1
    #generate Challenge Ci
    global Ci
    Ci =random.randrange(1, 2**32,7 %4)
    print("\n Challenge i.e., Ci generated by the server =",Ci)
    global challenges
    challenges = []
    for i in range(0,random_number):
        n = random.randrange(1, 2**32, 7 % 4)
        challenges.append(n)
    print ("\n Emergency challenges generated and stored in server are")
    for i in range(0,random_number):
        print(challenges[i])

    
    RFID(Ci,challenges)



def RFID(Ci,challenges): #2
    #generate Response ri for Challenge Ci
    global Ri
    global response
    response = []
    Ri =PUF(Ci) #repsonse pair is generated by using a random equation using PUF function
    for i in range (len(challenges)):
        response.append(PUF(challenges[i]))
    print("\n Response Ri generated by Tag for Challenge Ci using PUF =",Ri)
    print ("\n Emergency responses generated by RFID tag and stored in server are") 
    for i in range(0,random_number):
        print(response[i])

    

def PUF(challenge): #3
    return challenge* random.randrange(1, 2**32,7 %4)

    
if __name__ == "__main__":
    tid = 1000000000000000# generate an id for the tag
    print(" The id of RFID tag is",tid)
    Backend_Server()
    message_exchange_store(tid,challenges,response,Ci,Ri)
    tag_auth_phase()
    
    




