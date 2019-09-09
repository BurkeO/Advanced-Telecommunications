import socket, sys, ssl, time
from threading import Thread
from wsgiref.handlers import format_date_time
from datetime import datetime


blockedList = set()

BUFFSIZE = 1024
socketList = []
s = None

cache = {}              #the actual cache
dates = {}              #associated dates for url
cacheTiming = {}        #for url, record times for return from cache 
hostTiming = {}         #for url, record times for return from end server



def closeSockets(*sockets):                 # close sockets
    for curSocket in sockets:
        if curSocket:
            curSocket.close()
    if s:
        s.close()
    print("Shutting down")
    sys.exit(-1)


def userInputs(*sockets):                   #handle user input for blocking/unblocking of hosts
    userIn = input("\nWould you like to exit the proxy (type \"exit\") or block a URL (give a host) or unblock a host (\"r\")? (No input = show blocked list): ").lower()
    if userIn == 'exit':
        closeSockets(sockets)
    elif userIn == "":
        print ("Blocked = " + str(blockedList))
    elif userIn == "r":
        unblock = input("Provide a host to unblock : ")
        try:
            blockedList.remove(unblock)
            print("removed " + unblock)
        except KeyError:
            print("Host not in blocked list")
    else:
        blockedList.add(userIn.lower())
        print(userIn + " added to list")



def cacher(destHost, destPort, key, data):                  #Caching function
    start = time.time()                                         #start timer    
    responseToBrowser = b""                                     #response to send to browser

    if key in cache:                                            #check key is in cache
        forwardSocket = socket.socket()
        forwardSocket.connect((destHost, destPort))

        responseToBrowser = cache[key]                          #get the response from the cache

        details = str(data.decode()).split("\r\n")

        i = 0
        for string in details:
            if string.startswith("If-Modified-Since:"):
                details[i] = "If-Modified-Since: " + str(dates[key]) + "\r\n"
                break
            i = i + 1 

        newData = b""

        for string in details:
            if string is not '':
                new = string + "\r\n"
                newData += str.encode(new)

        forwardSocket.send(newData)                           #send of request to see if we get a 304


        rep = forwardSocket.recv(BUFFSIZE)

        if b"304" in rep:                                       #If is 304
            end = time.time()                                   #end the timer
            cacheTiming[key] = (end-start)                      #time it took to send data to browser from cache
            return responseToBrowser                            #return to browser
        else:
            toCache = rep                                       #cache new response from server
            while 1:
                rep = forwardSocket.recv(BUFFSIZE)
                if len(rep) > 0:
                    toCache += rep
                else:
                    break
            now = datetime.now()                                
            timeStamp = time.mktime(now.timetuple())
            dates[key] = format_date_time(timeStamp)            #update timestamp
            cache[key] = toCache                                #update data in cache
            print(str(key) + " updated")
            end = time.time()
            cacheTiming[key] = (end-start)                  
            return toCache

    else:
        return None

    



################################################################################################################### CACHING - http function to cache data - uncomment for caching

# def forwardData(destHost, destPort, browserConnection, data ,address):
#    try:
#        details = str(data.decode()).split("\r\n")
#        key = details[0]                                                               #obtain the url/key

#        starttime = time.time()                                                        #start timer

#        forwardSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#        forwardSocket.connect((destHost, int(destPort)))                               #connect socket to server
#        forwardSocket.sendall(data)                                                    #send to server


#        toCache = b""                                                                  #data to be cached

#        forwardSocket.setblocking(0)

#        while 1:
#            try:
#                rep = forwardSocket.recv(BUFFSIZE)                                     #take in reply
#                toCache = toCache + rep                                                #append to data to be cached
#                print ("\n")
#                browserConnection.send(rep)
#            except BlockingIOError:
#                break

#        now = datetime.now()
#        stamp = time.mktime(now.timetuple())
#        dates[key] = format_date_time(stamp)                                             #obtain date 
#        print("New entry : " + str(key))
#        cache[key] = toCache                                                            #add data to cache
#        endtime = time.time()                                                           #end timer
#        hostTiming[key] = (endtime-starttime)                                           #how long it took when asking server

#        forwardSocket.close()
#        browserConnection.close()
#    except KeyboardInterrupt:
#        userInputs(browserConnection, forwardSocket)

###########################################################################################################################################

# Non caching forwardData - comment out when caching

def forwardData(destHost, destPort, browserConnection, data ,address):
    try:
        forwardSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)           #create socket that is connected to end server
        forwardSocket.connect((destHost, int(destPort)))
        forwardSocket.sendall(data)
        while 1:
            rep = forwardSocket.recv(BUFFSIZE)                                      #take in response from server
            if(len(rep) <= 0):
                break
            print ("\n")
            browserConnection.sendall(rep)                                          #send response to browser
        forwardSocket.close()                                                       #close connections
        browserConnection.close()                                                   #close connections
    except KeyboardInterrupt:
        userInputs(browserConnection, forwardSocket)

############################################################################################################################################



def httpsForward(destHost, destPort, browserConnection, data ,address):
    try:
        httpsSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        response = b"HTTP/1.0 200 Connection Established\r\nConnection: close\r\nProxy-agent: Pyx\r\n\r\n\r\n"  #Relay 200 ok to browser to signal ready for transmission
        browserConnection.send(response)
        httpsSocket.connect((destHost, int(destPort)))                            #connect to server

        browserConnection.setblocking(0)                        #set connections as non-blocking (see https://docs.python.org/2/howto/sockets.html)
        httpsSocket.setblocking(0)
        while True:
            try:                                                #multiple try/excepts are so if client gives error, then try with server (with one big except = would have situation where
                req = browserConnection.recv(BUFFSIZE)          #   client gives error then try again immediately with the same client). 
                if len(req) <= 0:
                    break
                httpsSocket.send(req)                           #send data to/from browser to server
            except Exception:
                pass
            try:
                rep = httpsSocket.recv(BUFFSIZE)
                if len(rep) <= 0:
                    break
                browserConnection.send(rep)
            except Exception:
                pass
    except Exception:
        print(Exception)






def handle_browserConnection(data, browserConnection, address):
    try:
        isHttps = False
        details = str(data.decode()).split("\r\n")
        if details[0].startswith("CONNECT"):                            #Determine whether http/https
            isHttps = True
        hostIndex = 0
        i = 0
        for string in details:                                          
            if(string[ : 4] == "Host"):
                hostIndex = i
            i = i+1
        print ("\n")
        destHost = details[hostIndex][6:]                               #Find the host name and port in the incoming request

        if destHost.split(":")[0] not in blockedList:
            for string in details:
                print('\x1b[0;32;40m' + string + '\x1b[0m')             #Print request to management console
            destPortTemp = destHost.find(":")
            destPort = 0
            if(destPortTemp == -1 and isHttps == False):                
                destPort = 80                                           #Default port for http = 80
            elif(destPortTemp == -1 and isHttps == True):
                destPort = 443                                          #Default port for https = 443
            else:
                destPort = destHost[destPortTemp+1 :]
                destHost = destHost[ : destPortTemp]

######################################################################################################################## CACHING - uncomment for caching
            # key = details[0]
            # response = cacher(destHost, int(destPort), key, data)
            # time.sleep(1)
            # if response is not None:
            #    browserConnection.sendall(response)
            #    print("Found in cache : " + str(cacheTiming[key]))
            #    print("From host : " + str(hostTiming[key]))
            #    browserConnection.close()
            #    return
##########################################################################################################################


            if(isHttps == False):
                forwardData(destHost, destPort, browserConnection, data ,address)   #Begin http transmission
            else:
                httpsForward(destHost, destPort, browserConnection, data ,address)  #Begin https transmission

        else:
            print("This host is blocked\n")                                         #Return blocked host html
            browserConnection.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Blocked Host.</body></html>\r\n\r\n")
            browserConnection.close()
    except KeyboardInterrupt:
        userInputs(browserConnection)


#################################################################################################################################################################



def run():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       #Sets up socket.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 50000))                                #binds socket to localhost port xxxxxx.
        s.listen(15)                                                #Listen for connections made to the socket. 15 = max number of queued connections.  
        print("Listening...")     
    except Exception:
        print("Failure")
                                
                                
    while 1:
        try:
            (browserConnection, address) = s.accept()             #Accept incoming browserConnection. Returns connection details and addr.
            data = browserConnection.recv(BUFFSIZE)               #Receive max of 8192 bytes, at once, of incoming data. Returns string representation of data.
            thread = Thread(target = handle_browserConnection, args = (data, browserConnection, address)) 
            thread.daemon = True 
            thread.start()                                        #startNewthread to print and forward.                                                                   
        except KeyboardInterrupt:                                 #Allows for shutting down of proxy.
            userInputs()

    


run() #start proxy