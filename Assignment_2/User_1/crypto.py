from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import Crypto
import dropbox
import os
import zipfile

project = ""


def generateRSA_pairFiles(username):    # generate a public and private key pair for the given username and save in the relevant .pem files
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(pkcs=8, protection="scryptAndAES128-CBC")
    with open('./' + project + '/' + username + '_private_rsa_key.pem', 'wb') as f:
            f.write(encrypted_key)
    with open('./' + project +'/Public_Keys/' + username + '_rsa_public.pem', 'wb') as f:
            f.write(key.publickey().exportKey())


##########################################################


def encryptFile(username, fileToEncrypt): #encrypts file with sym key 
    with open('./' + project + '/Encrypted_Files/' + "Encrypted_" + fileToEncrypt, 'wb') as out_file:   # create the intial encrypted file
        with open('./' + project + '/' + username + '_private_rsa_key.pem', 'rb') as f:                        # get the user's private key
                data = f.read()
                key = RSA.importKey(data)
                cipher = PKCS1_OAEP.new(key)                                    
                plainSymKey = cipher.decrypt(open('./' + project + '/Sym_Keys/' + username + '_SymKey.bin', 'rb').read())  # decrypt the symmetric key for the user
                cipher = AES.new(plainSymKey, AES.MODE_ECB)
                data = open('./' + project + '/Original_Files/' + fileToEncrypt, 'rb').read()
                data = Crypto.Util.Padding.pad(data, 16, style = 'pkcs7')       # pad the file
                ciphertext = cipher.encrypt(data)       # encrypt the file with the decrypted symmetric key
                out_file.write(ciphertext)      # write to the encrypted file


############################################################


def decryptFile(username, fileToDecrypt, dbx): #decrypts the file with the sym key
    with open('./' + project + '/Encrypted_Files/' + fileToDecrypt, 'rb') as fobj:      # open the encrypted file
        with open('./' + project + '/' + username + '_private_rsa_key.pem', 'rb') as f:        # get the users private key
                dbx.files_download_to_file('./' + project + '/Sym_Keys/' + username + '_SymKey.bin', '/'+project+'/Sym_Keys/' + username + '_SymKey.bin') # get the most up to date sym keys
                data = f.read()
                key = RSA.importKey(data)
                cipher = PKCS1_OAEP.new(key)
                plainSymKey = cipher.decrypt(open('./' + project + '/Sym_Keys/' + username + '_SymKey.bin', 'rb').read())       # decrypt the sym key for the user with their private key
                data = fobj.read()
                cipher = AES.new(plainSymKey, AES.MODE_ECB)
                padDecrypt = cipher.decrypt(data)                                      # decrypt the encrypted file with the sym key
                orig  = Crypto.Util.Padding.unpad(padDecrypt, 16, style = 'pkcs7')      # unpad the data
                with open('./' + project + '/Decrypted_Files/' + "Decrypted_" + fileToDecrypt.split("Encrypted_")[1], 'wb') as f:
                    f.write(orig)       # write to the decrypted file


############################################################


def addUser(username, dbx):
        dbx.files_download_to_file('./' + project + '/members.txt', '/'+project+'/members/members.txt') # pull the members file
        f= open("./" + project + "/members.txt","a")
        f.write(username + "\n")        # write the new user to the file
        f.close()
        dbx.files_upload(open("./" + project + "/members.txt", 'rb').read(), '/'+project+'/members/members.txt', mode = dropbox.files.WriteMode('overwrite')) # push the updated members file


#############################################################


def encryptSymKeyForUser(username, adminName): # encrypt the symmetric key for a new user
        encryptZip = dbx.files_download_zip_to_file("./" + project + "/Public_Keys/pubKeyZip.zip", '/'+project+'/Public_Keys')
        zip_ref = zipfile.ZipFile("./" + project + "/Public_Keys/pubKeyZip.zip", 'r')
        zip_ref.extractall("./" + project)
        zip_ref.close()
        os.remove("./" + project + "/Public_Keys/pubKeyZip.zip")                # retrieve all the most up to date public keys from dropbox


        admin_private_key = RSA.import_key(open('./' + project + '/' + adminName + '_private_rsa_key.pem', 'rb').read()) # get the private key for the user that is doing the encrypting 
        cipher = PKCS1_OAEP.new(admin_private_key)
        plainSymKey = cipher.decrypt(open('./' + project + '/Sym_Keys/' + adminName + '_SymKey.bin', 'rb').read()) # decrypt the symmetric key

        key = RSA.importKey(open('./' + project + '/Public_Keys/' + username + '_rsa_public.pem').read()) # get the new users public key
        cipher = PKCS1_OAEP.new(key)
        encryptedSymKey = cipher.encrypt(plainSymKey)   # encrypt the symmetric key with the new users public key
        with open('./' + project + '/Sym_Keys/' + username + '_SymKey.bin', 'wb') as out_file:
                out_file.write(encryptedSymKey) # write out this encrypted sym key 


##############################################################


def genSymKey(adminName): # makes rsa keys and sym key for the first user
        generateRSA_pairFiles(adminName) # make rsa keys
        session_key = get_random_bytes(16) # make the symmetric key
        key = RSA.importKey(open('./' + project + '/Public_Keys/' + adminName + '_rsa_public.pem').read()) # get the users public key
        cipher = PKCS1_OAEP.new(key)
        encryptedSymKey = cipher.encrypt(session_key)   # encrypt the symmetric key
        with open('./' + project + '/Sym_Keys/' + adminName + '_SymKey.bin', 'wb') as out_file:
                out_file.write(encryptedSymKey) # write out the encrypted symmetric key


##############################################################


def removeUser(username, superUser, dbx) :
        dbx.files_download_to_file('./' + project + '/members.txt', '/'+project+'/members/members.txt') # pull the members file
        f = open("./" + project + "/members.txt","r")
        people = f.read()
        people = people.split("\n")     # get the names
        try:
                people.remove(username)         # remove the user
                f = open("./" + project + "/members.txt","w")
                people = "\n".join(people)
                f.write(people) # write back to the file
                f.close()
                dbx.files_upload(open("./" + project + "/members.txt", 'rb').read(), '/'+project+'/members/members.txt', mode = dropbox.files.WriteMode('overwrite')) # push the updated members list
                
                        ################ RE-ENCRYPT STUFF WITH NEW SYM KEY #############

                encryptZip = dbx.files_download_zip_to_file("./" + project + "/Encrypted_Files/encryptZip.zip", '/'+project+'/Encrypted_Files')
                zip_ref = zipfile.ZipFile("./" + project + "/Encrypted_Files/encryptZip.zip", 'r')
                zip_ref.extractall("./" + project)
                zip_ref.close()
                os.remove("./" + project + "/Encrypted_Files/encryptZip.zip")
                ####Pull encrypted files from dbx
                directory = "./" + project + "/Encrypted_Files/"
                for file in os.listdir(directory):
                        filename = os.fsdecode(file)
                        decryptFile(superUser, filename, dbx)   # decrypt all files

                session_key = get_random_bytes(16) # make the new symmetric key
                key = RSA.importKey(open('./' + project + '/Public_Keys/' + superUser + '_rsa_public.pem').read()) # get the users public key
                cipher = PKCS1_OAEP.new(key)
                encryptedSymKey = cipher.encrypt(session_key)   # encrypt the symmetric key
                with open('./' + project + '/Sym_Keys/' + superUser + '_SymKey.bin', 'wb') as out_file:
                        out_file.write(encryptedSymKey) # write out the encrypted symmetric key

                directory = "./" + project + "/Decrypted_Files/"       # re-encrypt all files
                for file in os.listdir(directory):
                        filename = os.fsdecode(file)
                        encryptFile(superUser, filename[10:])
                        dbx.files_upload(open("./" + project + "/Encrypted_Files/" + "Encrypted_" + filename[10:], 'rb').read(), '/'+project+'/Encrypted_Files/' + "Encrypted_" + filename[10:], mode = dropbox.files.WriteMode('overwrite'))
                        

                encryptZip = dbx.files_download_zip_to_file("./" + project + "/Public_Keys/pubKeyZip.zip", '/'+project+'/Public_Keys')
                zip_ref = zipfile.ZipFile("./" + project + "/Public_Keys/pubKeyZip.zip", 'r')
                zip_ref.extractall("./" + project)
                zip_ref.close()
                os.remove("./" + project + "/Public_Keys/pubKeyZip.zip")                # retrieve all the most up to date public keys from dropbox

                directory = "./" + project + "/Public_Keys/"       # re-encrypt all files
                for file in os.listdir(directory):
                        filename = os.fsdecode(file)
                        name = filename.split('_')[0]
                        if name not in people.split("\n"):
                                continue
                        key = RSA.importKey(open('./' + project + '/Public_Keys/' + name + '_rsa_public.pem').read()) # get the new users public key
                        cipher = PKCS1_OAEP.new(key)
                        encryptedSymKey = cipher.encrypt(session_key)   # encrypt the symmetric key with the new users public key
                        with open('./' + project + '/Sym_Keys/' + name + '_SymKey.bin', 'wb') as out_file:
                                out_file.write(encryptedSymKey) # write out this encrypted sym key 
                        dbx.files_upload(open('./' + project + '/Sym_Keys/' + name + '_SymKey.bin', 'rb').read(), "/"+project + "/Sym_Keys/" + name + "_SymKey.bin", mode = dropbox.files.WriteMode('overwrite'))

        except:
                print("This user is not in the group")

#############################################################


def getUserInput(username, command, dbx): # deals with all the user input
        if command.lower() == 'encrypt': # encrypt a file
                filename = input("Give a File Name :\n\t")
                try:
                        encryptFile(username, filename)
                        dbx.files_upload(open("./" + project + "/Encrypted_Files/" + "Encrypted_" + filename, 'rb').read(), '/'+project+'/Encrypted_Files/' + "Encrypted_" + filename)
                except FileNotFoundError:
                        print("File does not exist")

        elif command.lower() == 'decrypt': # decrypt a file
                ####Pull encrypted files from dbx
                try:
                        encryptZip = dbx.files_download_zip_to_file("./" + project + "/Encrypted_Files/encryptZip.zip", '/'+project+'/Encrypted_Files')
                        zip_ref = zipfile.ZipFile("./" + project + "/Encrypted_Files/encryptZip.zip", 'r')
                        zip_ref.extractall("./" + project)
                        zip_ref.close()
                        os.remove("./" + project + "/Encrypted_Files/encryptZip.zip")
                        ####Pull encrypted files from dbx

                        filename = input("Give a File Name :\n\t")
                        decryptFile(username, "Encrypted_" + filename, dbx)
                except:
                        print("No files have been encrypted yet")

        elif command.lower() == 'add user':
                newUser = input("Provide a new user name :\n\t")
                addUser(newUser, dbx) #add new user name to members file
                print("Wait for them to make their rsa keys.")

        elif command.lower() == 'remove user': # remove a user from the members file
                userToRemove = input("What user do you want to remove? : \n\t")
                removeUser(userToRemove, username, dbx)

        elif command.lower() == "sym key for user": # encrpyt a sym key for a new user
                newKeyRecv = input("Who are you encrypting the keys for? :\n\t")
                try:
                        encryptSymKeyForUser(newKeyRecv, username)
                        dbx.files_upload(open('./' + project + '/Sym_Keys/' + newKeyRecv + '_SymKey.bin', 'rb').read(), "/"+project + "/Sym_Keys/" + newKeyRecv + "_SymKey.bin") # push the new sym key
                        os.remove('./' + project + '/Sym_Keys/' + newKeyRecv + '_SymKey.bin')
                except:
                        print("This user is not in the group")

        elif command.lower() == 'quit': # quit the program
                exit(1)

        else:
                print("Invalid input. Try again") # invalid input


#########################################################################

def isInGroup(username, dbx): # check user is in group
        dbx.files_download_to_file('./' + project + '/members.txt', '/'+project+'/members/members.txt') # check they have the members file
        people = open("./" + project + "/members.txt","r").read()
        people = people.split("\n")
        if username in people:  # they are a members
                return True
        return False


#############################################################
#### MAIN ####
#############################################################


apiKey = input("Provide your access token :\n\t") # get access token
username = input("Provide your name :\n\t") # get name
dbx = dropbox.Dropbox(apiKey)
dbx.users_get_current_account() # initialise dropbox
project = input("Provide your shared project name :\n\t")

isAdmin = False
try:
        meta = dbx.files_get_metadata("/"+project+"/Public_Keys") # check are they making an initial project
except:
        print("You're the admin") # they are the first user
        isAdmin = True
        os.mkdir(project)
        os.mkdir("./" + project + "/Original_Files")
        os.mkdir("./" + project + "/Public_Keys")
        os.mkdir("./" + project + "/Sym_Keys")
        os.mkdir("./" + project + "/Encrypted_Files")
        os.mkdir("./" + project + "/Decrypted_Files")
        genSymKey(username) # make their keys

        directory = "./" + project + "/Public_Keys/"
        for file in os.listdir(directory):
                filename = os.fsdecode(file)
                dbx.files_upload(open(directory + filename, 'rb').read(), '/'+project+'/Public_Keys/' + filename) # upload the keys

        directory = "./" + project + "/Sym_Keys/"
        for file in os.listdir(directory):
                filename = os.fsdecode(file)
                dbx.files_upload(open(directory + filename, 'rb').read(), '/'+project+'/Sym_Keys/' + filename) # upload the keys

        f= open("./" + project + "/members.txt","w+")
        f.write(username + "\n")
        f.close()
        dbx.files_upload(open("./" + project + "/members.txt", 'rb').read(), '/'+project+'/members/members.txt') # make the members file

        
if isAdmin == False: # they are not making an initial project
        try:
                os.mkdir(project)
                os.mkdir("./" + project + "/Original_Files")
                os.mkdir("./" + project + "/Public_Keys")
                os.mkdir("./" + project + "/Sym_Keys")
                os.mkdir("./" + project + "/Encrypted_Files")
                os.mkdir("./" + project + "/Decrypted_Files")
        except:
                None
        dbx.files_download_to_file('./' + project + '/members.txt', '/'+project+'/members/members.txt') # check they have the members file

        #check is in members
        people = open("./" + project + "/members.txt","r").read()
        people = people.split("\n")
        if username in people:  # they are a members
                try:
                        meta = dbx.files_get_metadata("/"+project+"/Sym_Keys/" + username + "_SymKey.bin") # check do they have keys
                except:
                        ## make keys
                        generateRSA_pairFiles(username)             # they don't have keys - make their public and private keys and push the public key
                        for file in os.listdir("./" + project + "/Public_Keys/"):
                                filename = os.fsdecode(file)
                                dbx.files_upload(open("./" + project + "/Public_Keys/" + filename, 'rb').read(), '/'+project+'/Public_Keys/' + filename, mode = dropbox.files.WriteMode('overwrite'))
                        print("Made rsa keys")
                        print("Wait for a sym key to be encrypted for you") # wait for a symmetric key to be encrypted for you
                        exit(-1)
        else :
                print("No!!! You ain't in the group!!!") # the user is not a member
                exit(-1)
        print("You are in the group and you have keys") # they are a member and have their keys


while 1:
        command = input("Enter a command (encrypt, decrypt, add user, remove user, sym key for user) or 'quit':\n\t") # get the user input 
        if isInGroup(username, dbx):
                getUserInput(username, command, dbx) 
        else:
                print("You've been removed from the group")
                exit(-1)


###################################################