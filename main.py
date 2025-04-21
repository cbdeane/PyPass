#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################
#
# IMPORTANT INFORMATION ABOUT THE ARCHITECTURE OF THIS PROGRAM:
#
# THE OVERALL DATA STRUCTURE IS IN THE FOLLOWING FORMAT:
#
#   AUTH:
#       {USER_SHA512 : PASS_SHA512} -> user_table.csv
#   
#   ENCRYPTION:
#       {USER_SHA512 : RSA_ENCRYPTED_PRIVATE_KEY} -> priv_key_table.csv
#       {USER_SHA256 : RSA_ENCRYPTED_PUBLIC_KEY} -> pub_key_table.csv
#       
#   PASSWORD STORAGE:
#       {UUID_SHA256 : (RSA_ENCRYPTED_SERVICE_NAME, RSA_ENCRYPTED_SERVICE_USERNAME)} -> username_list.csv
#       {USER_SHA256 : [RSA_ENCRYPTED_UUID]} -> password_directory.csv
#       {UUID_SHA512 : RSA_ENCRYPTED_PASSWORD} -> password_list.csv
#
#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################

import hashlib
import getpass
import os
import platform
import sys
import uuid


from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

#####################################################################################
# INSTANTIATE THE GLOBAL VARIABLES
#####################################################################################
LOGGED_IN = False
USER_TABLE = {}
PRIV_KEY_TABLE = {}
PUB_KEY_TABLE = {}
PASSWORD_LIST = {}
USERNAME_LIST = {}
PASSWORD_DIRECTORY = {}
ACTIVE_USER = "PyPass"

#####################################################################################
#####################################################################################
#####################################################################################
# THIS CLASS HANDLES ALL FILE OPERATIONS FOR THE PROGRAM
#####################################################################################
#####################################################################################
#####################################################################################
class FileManager:
    #write the USER_TABLE to a CSV file
    def write_user_table(self):
        with open('user_table.csv', 'w') as f:
            for username, password in USER_TABLE.items():
                f.write(f"{username},{password}\n")

    #write the PRIV_KEY_TABLE to a CSV file
    def write_priv_key_table(self):
        with open('priv_key_table.csv', 'w') as f:
            for username, private_key in PRIV_KEY_TABLE.items():
                private_pem = self.serialize_private_key(private_key)
                f.write(f"{username},{private_pem}\n")

    # write the PUB_KEY_TABLE to a CSV file
    def write_pub_key_table(self):
        with open('pub_key_table.csv', 'w') as f:
            for username, public_key in PUB_KEY_TABLE.items():
                #Keys must be serialized prior to saving
                public_pem = self.serialize_public_key(public_key)
                f.write(f"{username},{public_pem}\n")

    # write the PASSWORD_LIST to a CSV file
    def write_password_list(self):
        with open('password_list.csv', 'w') as f:
            for uuid, password in PASSWORD_LIST.items():
                #RSA encrypted data must be b64 encoded to save
                password = b64encode(password).decode('utf-8')  # encode uuid to base64
                f.write(f"{uuid},{password}\n")

    # read the PASSWORD_LIST from a CSV file
    def read_password_list(self):
        try:
            with open('password_list.csv', 'r') as f:
                for line in f:
                    uuid, password = line.strip().split(',')
                    #must decode R64 that was used to save
                    password = b64decode(password)  # decode uuid from base64
                    PASSWORD_LIST[uuid] = password
        except FileNotFoundError:
            print("Password list file not found, starting with an empty password list.")

    # write the USERNAME_LIST to a CSV file
    def write_username_list(self):
        with open('username_list.csv', 'w') as f:
            for uuid, (name, username) in USERNAME_LIST.items():
                #RSA encrypted data must be b64 encoded to save
                name64 = b64encode(name).decode('utf-8')
                username64 = b64encode(username).decode('utf-8')
                f.write(f"{uuid},{name64},{username64}\n")

    # read the USERNAME_LIST from a CSV file
    def read_username_list(self):
        try:
            with open('username_list.csv', 'r') as f:
                for line in f:
                    uuid, name64, username64 = line.strip().split(',')
                    #must decode b64 that was used to save
                    name = b64decode(name64)
                    username = b64decode(username64)
                    USERNAME_LIST[uuid] = (name, username)
        except FileNotFoundError:
            print("Username list file not found, starting with an empty username list.")

    # write the PASSWORD_DIRECTORY to a CSV file
    def write_password_directory(self):
        with open('password_directory.csv', 'w') as f:
            for user_hash in PASSWORD_DIRECTORY:
                password_directory64 = {}
                password_directory64[user_hash] = []
                for uuid in PASSWORD_DIRECTORY[user_hash]:
                    #RSA encrypted data must be encoded with b64
                    uuid64 = b64encode(uuid).decode()  
                    password_directory64[user_hash].append(uuid64)
                uuid_string = ','.join(password_directory64[user_hash])
                f.write(f"{user_hash},{uuid_string}\n")

    # read the PASSWORD_DIRECTORY from a CSV file
    def read_password_directory(self):
        try:
            with open('password_directory.csv', 'r') as f:
                global PASSWORD_DIRECTORY
                PASSWORD_DIRECTORY = {}
                for line in f:
                    parsed_list = line.strip().split(',')
                    PASSWORD_DIRECTORY[parsed_list[0]] = []
                    for i in range (1, len(parsed_list)):
                        uuid64 = parsed_list[i]
                        #must decode b64 that was used to save
                        uuid = b64decode(uuid64)
                        PASSWORD_DIRECTORY[parsed_list[0]].append(uuid)
        except FileNotFoundError:
            print("Password directory file not found, starting with an empty password directory.")

    # read the USER_TABLE from a CSV file
    def read_user_table(self):
        try:
            with open('user_table.csv', 'r') as f:
                for line in f:
                    username, password = line.strip().split(',')
                    USER_TABLE[username] = password
        except FileNotFoundError:
            print("User table file not found, starting with an empty user table.")

    # read the PRIV_KEY_TABLE from a CSV file
    def read_priv_key_table(self):
        try:
            with open('priv_key_table.csv', 'r') as f:
                for line in f:
                    username, private_key = line.strip().split(',')
                    # private keys must be recreated
                    private_key = self.recreate_private_key(private_key)
                    # serialized data must be reconstructed 
                    private_keystring_rsa = self.deserialize_private_key(private_key)
                    PRIV_KEY_TABLE[username] = private_keystring_rsa
        except FileNotFoundError:
            print("Private key table file not found, starting with an empty private key table.")

    # read the PUB_KEY_TABLE from a CSV file
    def read_pub_key_table(self):
        try:
            with open('pub_key_table.csv', 'r') as f:
                for line in f:
                    username, public_key = line.strip().split(',')
                    # public key must be recreated
                    public_key = self.recreate_public_key(public_key)
                    # serialized data must be reconstructed
                    public_key_rsa = self.deserialize_public_key(public_key)
                    PUB_KEY_TABLE[username] = public_key_rsa
        except FileNotFoundError:
            print("Public key table file not found, starting with an empty public key table.")

    # loads all the files into memory
    def bootstrap_files(self):
        self.read_user_table()
        self.read_priv_key_table()
        self.read_pub_key_table()
        self.read_password_list()
        self.read_password_directory()
        self.read_username_list()

    # writes  all files
    def write_all_files(self):
        self.write_user_table()
        self.write_priv_key_table()
        self.write_pub_key_table()
        self.write_password_list()
        self.write_password_directory()
        self.write_username_list()

    # deserializes private keys
    def deserialize_private_key(self, key_data):
        private_key = None
        private_key = serialization.load_pem_private_key(
            key_data.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        return private_key
    
    # deserializes public keys
    def deserialize_public_key(self, key_data):
        public_key = serialization.load_pem_public_key(
            key_data.encode('utf-8'),
            backend=default_backend()
        )
        return public_key

    # serializes private keys
    def serialize_private_key(self, private_key):
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        # this portion of the function breaks the key apart for storage on one line
        single_line_private_pem_list = private_pem.splitlines()
        # this line removes the headers and footers
        single_line_private_pem_list = single_line_private_pem_list[1:-1]
        # this puts the entire thing together again on a single line as a string
        single_line_private_pem = ''.join(single_line_private_pem_list)
        return single_line_private_pem

    # serializes public keys
    def serialize_public_key(self, public_key):
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        # this portion of the function breaks the key apart for storage on one line
        single_line_public_pem_list = public_pem.splitlines()
        # this portion of the function removes the header and footer
        single_line_public_pem_list = single_line_public_pem_list[1:-1]
        # this portion puts the entire thing back together again on one line
        single_line_public_pem = ''.join(single_line_public_pem_list)
        return single_line_public_pem

    # this function recreates the key from a single line
    # this is necessary before deserialization
    def recreate_private_key(self, keystring):
        # write the header
        private_key = '-----BEGIN PRIVATE KEY-----'
        # break the line into 64 char sections
        while len(keystring) > 64:
            private_key += '\n' + keystring[:64]
            keystring = keystring[64:]
        # write the remainder to its own line (wont be an even 64 char)
        if len(keystring) > 0:
            private_key += '\n' + keystring
        # write the footer
        private_key += '\n-----END PRIVATE KEY-----'
        return private_key


    # this function recreates the key from a single line
    # this is necessary before deserialization
    def recreate_public_key(self, keystring):
        # write the header
        public_key = '-----BEGIN PUBLIC KEY-----'
        # break the line into 64 char sections
        while len(keystring) > 64:
            public_key += '\n' + keystring[:64]
            keystring = keystring[64:]
        # write the remainder to its own line 
        if len(keystring) > 0:
            public_key += '\n' + keystring
        # write the footer
        public_key += '\n-----END PUBLIC KEY-----'
        return public_key

#####################################################################################
# THIS FUNCTION IS FOR DEBUGGING PURPOSES
#####################################################################################
def debug():
    print("USER_TABLE: ", USER_TABLE)
    print("PRIV_KEY_TABLE: ", PRIV_KEY_TABLE)
    print("PUB_KEY_TABLE: ", PUB_KEY_TABLE)
    print("PASSWORD_LIST: ", PASSWORD_LIST)
    print("PASSWORD_DIRECTORY: ", PASSWORD_DIRECTORY)
    print("ACTIVE_USER: ", ACTIVE_USER)
    print("")

#####################################################################################
# THIS FUNCTION CLEARS THE SCREEN ON MULTIPLE OSes SO THE PROGRAM
# DOESNT HAVE TO BE SO UGLY
#####################################################################################

def clear_terminal():
    os.system("cls" if platform.system() == "Windows" else "clear")


#####################################################################################
# THIS FUNCTION EXITS THE PROGRAM GRACEFULLY
#####################################################################################

def exit_gracefully():
    clear_terminal()
    sys.exit(0)

#####################################################################################
# THIS FUNCTION MAKES A CLASSY SPLASHSCREEN FOR THE PROGRAM
#####################################################################################
def display_splashscreen():
    #FIRST CLEAR THE TERMINAL, I AM THE CAPTAIN NOW
    clear_terminal()

    #PRINT THE SPLASHSCREEN
    print(r"                                       ")
    print(r"                                       ")
    print(r"   ___________________________________              /^\/^\ ")
    print(r"  |  ______     ______                |           _|__|  O|")
    print(r"  |  | ___ \    | ___ \               |  \/     /~     \_/ \ ")
    print(r"  |  | |_/ /   _| |_/ /_ _ ___ ___    |   \____|__________/  \ ")
    print(r"  |  |  __/ | | |  __/ _` / __/ __|   |         \_______      \ ")
    print(r"  |  | |  | |_| | | | (_| \__ \__ \   |                  `\     \                 \ ")
    print(r"  |  \_|   \__, \_|  \__,_|___/___/   |                    |     |                  \ ")
    print(r"  |         __/ |                     |                   /      /                    \ ")
    print(r"  |        |___/                      |                  /     /                       \\ ")
    print(r"  |                                   |                /      /                         \ \ ")  
    print(r"  |  A Python Password Manager        |               /     /                            \  \ ")
    print(r"  |  By: Charles Deane                |             /     /             _----_            \   \ ") 
    print(r"  |___________________________________|            /     /           _-~      ~-_         |   |")
    print(r"                                                  (      (        _-~    _--_    ~-_     _/   |")
    print(r"    to get started try typing 'start'              \      ~-____-~    _-~    ~-_    ~-_-~    /")
    print(r"                                                     ~-_           _-~          ~-_       _-~")
    print(r"                                                        ~--______-~                ~-___-~")
    print(r"                                       ")


#####################################################################################
# THIS FUNCTION DISPLAYS THE HELPBOX
#####################################################################################
def display_help():
    print("   ______________________________________________________")
    print("  |  Here are the commands you can use:                  |")
    print("  |                                                      |")
    print("  |  - start: displays the getting started instructions  |")
    print("  |  - help: displays the help message                   |")
    print("  |  - clear: clears the terminal                        |")
    print("  |  - exit: exits the program                           |")
    print("  |  - register: registers a new user                    |")
    print("  |  - login: logs in an existing user account           |")
    print("  |  - logout: logs out the current user session         |")
    print("  |  - whoami: shows the active user (also in prompt)    |")
    print("  |  - passwd: changes your PyPass password              |")
    print("  |  - view: views all passwords                         |")
    print("  |  - reveal: reveals passwords in plaintext            |")
    print("  |  - add: adds a new password                          |")
    print("  |  - delete: deletes a password                        |")
    print("  |  - update: updates a password                        |")
    print("  |______________________________________________________|")
    print("")


#####################################################################################
# THIS FUNCTION DISPLAYS THE START INSTRUCTIONS
#####################################################################################
def display_start():
    print("   ___________________________________________________ ")
    print("  |                                                   |")
    print("  |  PyPass is a multi user password manager          |")
    print("  |                                                   |")
    print("  |  To get started, try following these easy steps!  |")
    print("  |                                                   |")
    print("  |    1 - Type 'register' and make an account.       |")
    print("  |    2 - Type 'login' to enter your account.        |")
    print("  |    3 - For more commands try typing 'help'        |")
    print("  |___________________________________________________|")
    print("")


#####################################################################################
# THIS FUNCTION DISPLAYS INSTRUCTIONS FOR THE 'REVEAL' COMMAND
#####################################################################################
def reveal_instructions():
    print("   ____________________________________________________")
    print("  |                                                    |")
    print("  |  reveal all - Displays all passwords in plaintext  |")
    print("  |                                                    |")
    print("  |  reveal UUID - Displays one password in plaintext  |")
    print("  |                                                    |")
    print("  |  For security reasons, it is reccomended to        |")
    print("  |  only view one pass at a time.                     |")
    print("  |                                                    |")
    print("  |  Please remember to use the 'clear' command after  |")
    print("  |  you have finished!                                |")
    print("  |____________________________________________________|")
    print("")


#####################################################################################
# THIS FUNCTION DISPLAYS INSTRUCTIONS FOR THE 'DELETE' COMMAND
#####################################################################################
def delete_instructions():
    print("   ____________________________________________________")
    print("  |                                                    |")
    print("  |  delete UUID - Deletes a password from the list    |")
    print("  |                                                    |")
    print("  |  To find your UUID, try the 'view' command.        |")
    print("  |____________________________________________________|")
    print("")


#####################################################################################
# THIS FUNCTION DISPLAYS INSTRUCTIONS FOR THE 'UPDATE' COMMAND
#####################################################################################
def update_instructions():
    print("   ____________________________________________________")
    print("  |                                                    |")
    print("  |  update UUID - Updates a password in the list      |")
    print("  |                                                    |")
    print("  |  To find your UUID, try the 'view' command.        |")
    print("  |____________________________________________________|")
    print("")


#####################################################################################
# THIS FUNCTION CREATES A SHORTENED UUID FOR THE PASSWORD HASH TABLE INDEXES
#####################################################################################
def uuid_short():
    return uuid.uuid4().hex[:6]
    
#####################################################################################
# THIS FUNCTION GETS THE USERNAME FROM THE USER AND RETURNS A TUPLE
# INDEX 0 -> USERNAME IN PLAINTEXT
# INDEX 1 -> HASHED USERNAME
# ARGS: prompt -> THE PROMPT TO DISPLAY TO THE USER
#####################################################################################

def get_username_from_user(prompt):

    #gather username input
    username_input = input(prompt)

    # remove any whitespace and make it lowercase for validation
    username_input = username_input.strip()
    username_input = username_input.lower()

    # perform the hashing
    username_encoded = username_input.encode('utf-8')
    username_hash512 = hashlib.sha512(username_encoded).hexdigest()
    username_hash256 = hashlib.sha256(username_encoded).hexdigest()

    # return the tuple
    return (username_input, username_hash512, username_hash256)


#####################################################################################
# THIS FUNCTION GETS THE PASSWORD FROM THE USER AND RETURNS A HASHED PASSWORD
# ARGS: prompt -> THE PROMPT TO DISPLAY TO THE USER
#####################################################################################

def get_password_from_user(prompt):
    # immediately hash upon input
    # no need to remove whitespace and make it lowercase before hashing
    password_input = getpass.getpass(prompt).encode('utf-8')
    password_input = hashlib.sha512(password_input).hexdigest()
    return password_input



#####################################################################################
# THIS FUNCTION GENERATES A KEY PAIR FOR THE USER
# KEYS ARE RETURNED IN A TUPLE
# INDEX 0 -> PUBLIC KEY
# INDEX 1 -> PRIVATE KEY
#####################################################################################

def generate_key_pair():

    # GENERATE A PRIVATE KEY
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    #GENERATE A PUBLIC KEY COUNTERPARTY
    public_key = private_key.public_key()

    return(public_key, private_key)


#####################################################################################
# THIS FUNCTION ENCRYPTS DATA USING THE PUBLIC KEY
#####################################################################################

def encrypt_data(data, public_key):
    # nested function so that error handling can be done locally
    def encrypt_data_encoded(data, public_key):
        # encrypt the data using the public key
        # MFG1 is the mask generation function
        # OAEP is the padding scheme
        encrypted_data = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        return encrypted_data

    # try to encode the data, if it fails then encode it as utf-8
    # if it  cannot be encrypted after encoding then return None
    try:
        encrypt_data_encoded(data, public_key)
    except TypeError:
        data = data.encode('utf-8')
        try:
            encrypt_data_encoded(data, public_key)
        except:
            print("Error: Data could not be encrypted")
            return None
    return encrypt_data_encoded(data, public_key)


#####################################################################################
# THIS FUNCTION DECRYPTS THE DATA USING THE PRIVATE KEY
#####################################################################################

def decrypt_data(ciphertext, private_key):
    # decrypt with the same scheme as the encryption
    bit_text = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

    #decode the data before returning
    plaintext = bit_text.decode('utf-8')
    return plaintext


#####################################################################################
# THIS FUNCTION LOGS THE USER IN
#####################################################################################
        
def login_user():

    # NESTED FUNCTION TO CHECK IF THE USERNAME AND PASSWORD MATCH
    # username input for this function must be the hashed username
    def login_check(username, password):
        if username in USER_TABLE:
            if USER_TABLE[username] == password:
                return True
            else:
                return False
    # CHECKS FOR INITIAL LOGIN
    # GIVES THE USER 3 ATTEMPTS TO LOGIN
    for i in range(3):
        # gather login information
        username = get_username_from_user("Username: ")
        password = get_password_from_user("Password: ")
        # run a login check
        if login_check(username[1], password):

            # change the appropriate global variables on login
            global ACTIVE_USER
            ACTIVE_USER = username[0]
            global LOGGED_IN
            LOGGED_IN = True

            # let the user know that login is successful
            print("Login successful!")

            return

        # if the login fails 3 times, give the user a message
        elif i == 2:
            print("Login failed, 3 try limit reached")
            return

        # if the login fails, give the user a message
        else:
            print("Login failed, please try again.")

 
#####################################################################################
# THIS FUNCTION CREATES A NEW USER 
# RETURN TYPE IS EITHER FALSE OR A TUPLE
# IF IT IS A TUPLE THEN:
# INDEX 0 -> USERNAME
# INDEX 1 -> PASSWORD
#####################################################################################

def create_new_user():
    # GETS THE USERNAME OF THE USER AND CHECKS IF IT ALREADY EXISTS
    def instantiate_username():

        # get the username from the user
        new_user_input = get_username_from_user("Enter a username: ")

        # make sure the user is not using the default low-level user pypass
        if new_user_input[0].lower() == "pypass":
            print("Username cannot be 'PyPass'")
            print("Please try again.")
            return instantiate_username()

        # make sure the hashed username is not already in the user table
        if new_user_input[1] in USER_TABLE:
            print("Username already exists")
            print("Please try again.")
            return instantiate_username()
        else:
            return (new_user_input, True)

    # GETS THE PASSWORD TWICE AND MAKES SURE THEY MATCH
    def instantiate_password():
        new_password_input = get_password_from_user("Enter a password: ")
        new_password_input_confirmation = get_password_from_user("Confirm your password: ")
        return (new_password_input, new_password_input == new_password_input_confirmation)

    # INSTANTIATES new_user_input
    # GETS USERNAME
    # IF THE USERNAME IS NOT IN THE USER TABLE, IT CREATES A NEW USER
    # AFTER 3 FAILED ATTEMPTS, IT RETURNS FALSE AND EXITS THE FUNCTION
    # new_user_input set to none so that it can be checked later
    new_user_input = None
    for i in range (3):
        username_creation_tuple = instantiate_username()
        if username_creation_tuple[1]:
            new_user_input = username_creation_tuple[0]
            break
        elif i == 2 and username_creation_tuple[1] == False:
            print("\nUsername already exists, 3 try limit reached\n")
            return False
        else:
            print("\nUsername already exists, please try again.\n")

    # check if new_user_input is None
    try:
        assert new_user_input != None, "Critical error, username data type is invalid"
    except AssertionError as e:
        print(f"AssertionError: {e}")
        print("Cannot create user at this time")
        return False


    # GETS PASSWORD
    # CHECKS IF THE PASSWORDS MATCH
    # AFTER 3 FAILED ATTEMPTS, IT RETURNS FALSE AND EXITS THE FUNCTION
    for i in range (3):
        password_creation_tuple = instantiate_password()
        if password_creation_tuple[1]:
            return (new_user_input, password_creation_tuple[0])
        elif i == 2 and password_creation_tuple[1] == False:
            print("\nPasswords do not match, 3 try limit reached\n")
            return False
        else:
            print("\nPasswords do not match, please try again.\n")


#####################################################################################
# THIS FUNCTION ADDS A NEW USER TO THE USER TABLE
#####################################################################################

def register_new_user():
    
    #create a new user before adding them to the user table
    try:
        new_user = create_new_user()
    except:
        print("Error: User could not be created")
        return False
    
    if new_user:
        # generates the key that the user will use for passwords
        user_keys = generate_key_pair()

        # adds sha512 username in the format {username: password}
        USER_TABLE[new_user[0][1]] = new_user[1]

        # adds sha512 username in the form {username: private_key}
        PRIV_KEY_TABLE[new_user[0][1]] = user_keys[1]

        # adds sha256 username in the form {username: public_key}
        PUB_KEY_TABLE[new_user[0][2]] = user_keys[0]

        print("New user created successfully!")


#####################################################################################
# THIS FUNCTION CHANGES THE USER'S PASSWORD
#####################################################################################

def change_user_password():
    # gives the user 3 attempts to change their password
    for i in range(3):
        # get the old password from the user
        old_password = get_password_from_user("Enter your old password: ")

        # check if the old password matches the hashed active user
        # if successful then the user has to enter the new password twice
        hashed_active_user = hashlib.sha512(ACTIVE_USER.encode('utf-8')).hexdigest()
        if USER_TABLE[hashed_active_user] == old_password:
            new_password = get_password_from_user("Enter your new password: ")
            new_password_confirmation = get_password_from_user("Confirm your new password: ")
            if new_password == new_password_confirmation:
                USER_TABLE[hashed_active_user] = new_password
                print("\nPassword changed successfully!")
                return (True, USER_TABLE)
            else:
                print("\nPasswords do not match, please try again.\n")
        elif i == 2:
            print("\nPassword change failed, 3 try limit reached")
            return (False)
        else:
            print("\nPassword change failed, please try again.\n")


#####################################################################################
# THIS FUNCTION ADDS A PASSWORD TUPLE TO THE PASSWORD LIST
# PASSWORD TUPLE IS IN THE FORMAT:
# (username_hash, name_input, encrypted_username, encrypted_password)
#####################################################################################

def create_password():

    # get the name and username from the user
    name_input = input("Enter the quick-name for this account: ")
    username_input = input("Enter the username for this account: ")

    #give the user 3 attempts
    for i in range (3):

        # get the password from the user twice for confirmation
        password_input = getpass.getpass("Enter the password for this account: ")
        password_confirmation_input = getpass.getpass("Confirm the password for this account: ")

        # if the passwords match then hash the username, encrypt the data, and return a tuple with the data
        if password_input == password_confirmation_input:
            # get all the data in the proper format for structuring
            current_user_pub_hash = hashlib.sha256(ACTIVE_USER.encode('utf-8')).hexdigest()
            encrypted_password = encrypt_data(password_input, PUB_KEY_TABLE[current_user_pub_hash])
            encrypted_username = encrypt_data(username_input, PUB_KEY_TABLE[current_user_pub_hash])
            encrypted_name = encrypt_data(name_input, PUB_KEY_TABLE[current_user_pub_hash])

            # generate an index value for the hashmaps
            uuid = uuid_short()

            # generate all the variations of value for the hashmaps
            uuid_sha512 = hashlib.sha512(uuid.encode('utf-8')).hexdigest()
            uuid_sha256 = hashlib.sha256(uuid.encode('utf-8')).hexdigest()
            uuid_encrypted = encrypt_data(uuid, PUB_KEY_TABLE[current_user_pub_hash])

            # add the data to the hashmaps
            # USERNAME_LIST is in the format {username_hash: (encrypted_name, encrypted_username)}
            USERNAME_LIST[uuid_sha256] = (encrypted_name, encrypted_username)
            # PASSWORD_LIST is in the format {uuid_sha512: encrypted_password}
            PASSWORD_LIST[uuid_sha512] = encrypted_password

            # PASSWORD_DIRECTORY is in the format {username_hash: [uuid_encrypted]}
            # MUST EXCEPT KEYERROR BECAUSE THE USER MAY NOT HAVE ANY PASSWORDS
            try:
                PASSWORD_DIRECTORY[current_user_pub_hash].append(uuid_encrypted)
            except KeyError:
                PASSWORD_DIRECTORY[current_user_pub_hash] = [uuid_encrypted]

            print("Password added successfully!")

            # return the function so that there arent cases of adding pass multiple times
            return

        # block the user out if they fail 3 times
        elif i == 2:
            print("\nPasswords do not match, 3 try limit reached\n")

        # give the user a message if the passwords to not match
        else:
            print("\nPasswords do not match, please try again.\n")


#####################################################################################
# THIS FUNCTION GETS THE USER INPUT AND PARSES INTO A LIST
#####################################################################################

def get_user_input():

    # if the user is logged in give them a ~ on their prompt like linux
    if LOGGED_IN:
        user_input = input(ACTIVE_USER + " ~ ")

    # if the user is not logged in give them a > on their prompt like windows or zsh
    else:
        user_input = input(ACTIVE_USER + " > ")

    # always make user input lowercase so it is easier to match
    user_input = user_input.lower()

    # split the user input into a list for parsing
    user_input = user_input.split()

    #return the final user input after processing
    return user_input


#####################################################################################
# THIS FUNCTION LOGS THE USER OUT
#####################################################################################

def logout_user():

    # pulls global variables into scope
    global LOGGED_IN
    global ACTIVE_USER

    #logs the user out and sets the active user to PyPass
    LOGGED_IN = False
    ACTIVE_USER = "PyPass"

    # clears the terminal
    clear_terminal()


#####################################################################################
# THIS FUNCTION SHOWS A LIST OF ALL PASSWORDS AVAILABLE TO THE USER
#####################################################################################

def show_passwords():
    # get the necesary hashes for the active user
    active_user_priv_hash = hashlib.sha512(ACTIVE_USER.encode('utf-8')).hexdigest()
    active_user_pub_hash = hashlib.sha256(ACTIVE_USER.encode('utf-8')).hexdigest()

    # gets the list of encrypted UUIDs for the active user
    try:
        uuid_list = PASSWORD_DIRECTORY[active_user_pub_hash]
    except KeyError:
        print("No passwords found for this user.")
        return


    # create the lists for the UUIDs
    uuid_plaintext = []
    service_plaintext = []
    username_stars = []
    password_stars = []

    # iterate through the list of UUIDs, decrypt and organize the data
    # IDE MAY GIVE WARNING BUT UUID IS ALREADY CHECKED FOR KEY ERRORS
    for uuid in uuid_list:
        # decrypt the UUID and append to respective list
        decrypted_uuid = decrypt_data(uuid, PRIV_KEY_TABLE[active_user_priv_hash])
        uuid_plaintext.append(decrypted_uuid)

        # get the hashes of the UUID and append to their respective lists
        uuid_sha512 = hashlib.sha512(decrypted_uuid.encode('utf-8')).hexdigest()
        uuid_sha256 = hashlib.sha256(decrypted_uuid.encode('utf-8')).hexdigest()

        # get the encrypted items from their respective data structures
        encrypted_name = USERNAME_LIST[uuid_sha256][0]
        encrypted_username = USERNAME_LIST[uuid_sha256][1]
        encrypted_password = PASSWORD_LIST[uuid_sha512]

        # decrypt the password and username
        # append to the respective lists
        # because so much data may be sensitive it will only show stars
        # the user must reveal passwords explicitly in other functions
        password_stars.append(
                len(decrypt_data(encrypted_password, PRIV_KEY_TABLE[active_user_priv_hash])) * "*"
        )
        username_stars.append(
            len(decrypt_data(encrypted_username, PRIV_KEY_TABLE[active_user_priv_hash])) * "*"
        )
        service_plaintext.append(
            decrypt_data(encrypted_name, PRIV_KEY_TABLE[active_user_priv_hash])
        )
        
    # try to print by passing the lists through the print_password_table function
    try:
        print_password_table(uuid_plaintext, service_plaintext, username_stars, password_stars)
    except:
        print("Unable to print password table, please try again.")

#####################################################################################
# THIS FUNCTION REVEALS A LIST OF ALL PASSWORDS AVAILABLE TO THE USER
#####################################################################################

def reveal_passwords():
    # get the necesary hashes for the active user
    active_user_priv_hash = hashlib.sha512(ACTIVE_USER.encode('utf-8')).hexdigest()
    active_user_pub_hash = hashlib.sha256(ACTIVE_USER.encode('utf-8')).hexdigest()

    # gets the list of encrypted UUIDs for the active user
    try:
        uuid_list = PASSWORD_DIRECTORY[active_user_pub_hash]
    except KeyError:
        print("No passwords found for this user.")
        return

    # create the lists for the UUIDs
    uuid_plaintext = []
    service_plaintext = []
    username_stars = []
    password_stars = []

    # iterate through the list of UUIDs, decrypt and organize the data
    # IDE MAY GIVE WARNING BUT THE CONDITION FOR KEY ERROR IS CHECKED BEFORE CREATING LISTS
    for uuid in uuid_list:
        # decrypt the UUID and append to respective list
        decrypted_uuid = decrypt_data(uuid, PRIV_KEY_TABLE[active_user_priv_hash])
        uuid_plaintext.append(decrypted_uuid)

        # get the hashes of the UUID and append to their respective lists
        uuid_sha512 = hashlib.sha512(decrypted_uuid.encode('utf-8')).hexdigest()
        uuid_sha256 = hashlib.sha256(decrypted_uuid.encode('utf-8')).hexdigest()

        # get the encrypted items from their respective data structures
        encrypted_name = USERNAME_LIST[uuid_sha256][0]
        encrypted_username = USERNAME_LIST[uuid_sha256][1]
        encrypted_password = PASSWORD_LIST[uuid_sha512]

        # decrypt the password and username
        # append to the respective lists
        password_stars.append(
            decrypt_data(encrypted_password, PRIV_KEY_TABLE[active_user_priv_hash])
        )
        username_stars.append(
            decrypt_data(encrypted_username, PRIV_KEY_TABLE[active_user_priv_hash])
        )
        service_plaintext.append(
            decrypt_data(encrypted_name, PRIV_KEY_TABLE[active_user_priv_hash])
        )
        
    # try to print by passing the lists through the print_password_table function
    try:
        print_password_table(uuid_plaintext, service_plaintext, username_stars, password_stars)
    except:
        print("Unable to print password table, please try again.")


#####################################################################################
# THIS FUNCTION REVEALS A SINGLE PASSWORD TO THE USER
#####################################################################################

def reveal_password_uuid(uuid):

    # get the active user private hash for decryption
    active_user_priv_hash = hashlib.sha512(ACTIVE_USER.encode('utf-8')).hexdigest()
    active_user_pub_hash = hashlib.sha256(ACTIVE_USER.encode('utf-8')).hexdigest()

    # check uuid validity
    if validate_uuid(uuid, active_user_pub_hash, active_user_priv_hash):
        pass
    else:
        print("unable to validate UUID")
        return

    # get the necesary hashes for the uuid
    uuid_512 = hashlib.sha512(uuid.encode('utf-8')).hexdigest()
    uuid_256 = hashlib.sha256(uuid.encode('utf-8')).hexdigest()

    # create the lists for the UUIDs
    uuid_plaintext = [uuid]
    service_plaintext = []
    username_plaintext = []
    password_plaintext = []

    # append the decrypted data to the respective lists
    service_plaintext.append(
        decrypt_data(
            USERNAME_LIST[uuid_256][0], 
            PRIV_KEY_TABLE[active_user_priv_hash]
        )
    )

    username_plaintext.append(
        decrypt_data(
            USERNAME_LIST[uuid_256][1], 
            PRIV_KEY_TABLE[active_user_priv_hash]
        )
    )

    password_plaintext.append(
        decrypt_data(
            PASSWORD_LIST[uuid_512], 
            PRIV_KEY_TABLE[active_user_priv_hash]
        )
    )

    #print the data
    try:
        print_password_table(uuid_plaintext, service_plaintext, username_plaintext, password_plaintext)
    except:
        print("Unable to print password table, please try again.")




#####################################################################################
# THIS COMMAND FORMATS THE FIRST COLUMN OF THE PASSWORD TABLE
#####################################################################################
def format_first_column(column):
    # format each element to have line dividers, and make it so each string is the same length
    # this way theh table will be square, and the divider lines will be straight
    longest_element = max(len(str(element)) for element in column)
    result = []
    for i in range(len(column)):
        element = "  |   " + str(column[i]) + (" " * (longest_element - len(str(column[i])))) + "   |"
        result.append(element)
    return result


#####################################################################################
# THIS COMMAND FORMATS THE COLUMNS FOR THE PASSWORD TABLE
#####################################################################################
def format_column(column):
    # format each element to have line dividers, and make it so each string is the same length
    # this way theh table will be square, and the divider lines will be straight
    longest_element = max(len(str(element)) for element in column)
    result = []
    for i in range(len(column)):
        element = "   " + str(column[i]) + (" " * (longest_element - len(str(column[i])))) + "   |"
        result.append(element)
    return result


#####################################################################################
# THIS COMMAND PRINTS THE PASSWORD TABLE
#####################################################################################
def print_password_table(uuid, name, username, password):

    # throw an error if the data is not the same length
    assert len(uuid) == len(name) == len(username) == len(password), "Error: Data is not the same length"

    # add the headers to each colmn
    uuid_column = ['UUID:'] + uuid
    name_column = ['Name:'] + name
    username_column = ['Username:'] + username
    password_column = ['Password:'] + password

    # format all the columns        
    uuid_column = format_first_column(uuid_column)
    name_column = format_column(name_column)
    username_column = format_column(username_column)
    password_column = format_column(password_column)

    #print the topbar
    print("  +" + "-" * (len(uuid_column[0]) + len(name_column[0]) + len(username_column[0]) + len(password_column[0]) - 1) + "+")

    #print the data
    for i in range(len(uuid) + 1):
        print(f"{uuid_column[i]} {name_column[i]} {username_column[i]} {password_column[i]}")

    #print the bottom bar
    print("  +" + "-" * (len(uuid_column[0]) + len(name_column[0]) + len(username_column[0]) + len(password_column[0]) - 1) + "+")


#####################################################################################
# THIS FUNCTION USED TOVALIDATE UUIDs
#####################################################################################
def validate_uuid(uuid, active_user_pub_hash, active_user_priv_hash):
    # check for errors, or to see if the uuid might not belong to the user.
    # if there is a KeyError or the uuid isn't in the password directory then
    # the function is returned
    if active_user_pub_hash in PASSWORD_DIRECTORY:
        try:
            for id in PASSWORD_DIRECTORY[active_user_pub_hash]:
                if uuid == decrypt_data(id, PRIV_KEY_TABLE[active_user_priv_hash]):
                    return True
        except KeyError:
            print("UUID not found for this user.")
            return
    return False


#####################################################################################
# THIS FUNCTION DELETES A PASSWORD FROM THE PASSWORD LIST
#####################################################################################

def delete_password(uuid):
    # get the active user private hash for decryption
    active_user_priv_hash = hashlib.sha512(ACTIVE_USER.encode('utf-8')).hexdigest()
    active_user_pub_hash = hashlib.sha256(ACTIVE_USER.encode('utf-8')).hexdigest()

    # check uuid validity
    if validate_uuid(uuid, active_user_pub_hash, active_user_priv_hash):
        pass
    else:
        print("unable to validate UUID")
        return

    # get the uuid hashes  
    uuid_512 = hashlib.sha512(uuid.encode('utf-8')).hexdigest()
    uuid_256 = hashlib.sha256(uuid.encode('utf-8')).hexdigest()

    # delete the data from the hashmaps
    del USERNAME_LIST[uuid_256]
    del PASSWORD_LIST[uuid_512]
    
    for password in PASSWORD_DIRECTORY[active_user_pub_hash]:
        if uuid == decrypt_data(password, PRIV_KEY_TABLE[active_user_priv_hash]):
            PASSWORD_DIRECTORY[active_user_pub_hash].remove(password)
            break
    
    # test to make sure things are deleted and print success messages
    print("running checks to confirm deletion...\n")
    try:
        assert uuid_256 not in USERNAME_LIST, "Error: UUID not deleted from USERNAME_LIST"
        print("[*] PASSED CHECK 1/3")
        assert uuid_512 not in PASSWORD_LIST, "Error: UUID not deleted from PASSWORD_LIST"
        print("[*] PASSED CHECK 2/3")
        assert uuid not in PASSWORD_DIRECTORY[active_user_pub_hash], "Error: UUID not deleted from PASSWORD_DIRECTORY"
        print("[*] PASSED CHECK 3/3")
    except AssertionError as e:
        print(f"AssertionError: {e}")
        print("\nError: Password not deleted")
        return False
    print("\nPassword deleted successfully!")
    return True


#####################################################################################
# THIS FUNCTION UPDATES A PASSWORD IN THE PASSWORD LIST
#####################################################################################
def update_password(uuid):
    # get the active user private hash for decryption
    active_user_priv_hash = hashlib.sha512(ACTIVE_USER.encode('utf-8')).hexdigest()
    active_user_pub_hash = hashlib.sha256(ACTIVE_USER.encode('utf-8')).hexdigest()

    # check uuid validity
    if validate_uuid(uuid, active_user_pub_hash, active_user_priv_hash):
        pass
    else:
        print("unable to validate UUID")
        return

    for i in range(3):
        # get the new password from the user
        new_password = getpass.getpass("Enter your new password: ")
        new_password_confirmation = getpass.getpass("Confirm your new password: ")

        # check if the passwords match
        # if they match encrypt the password, and update the hashmaps
        if new_password == new_password_confirmation:
            encrypted_password = encrypt_data(new_password, PUB_KEY_TABLE[active_user_pub_hash])
            uuid_512 = hashlib.sha512(uuid.encode('utf-8')).hexdigest()
            PASSWORD_LIST[uuid_512] = encrypted_password
            print("Password updated successfully!")
            return
        elif i == 2:
            print("\nPasswords do not match, 3 try limit reached\n")
            return
        else:
            print("Passwords do not match, please try again.")


#####################################################################################
#
#####################################################################################
def logged_out_user_using_logged_in_command():
    print("You must be logged in to use this command")
    print("Try using the 'start' command for information about how to get started")

#####################################################################################
#####################################################################################
#####################################################################################
# THIS IS WHERE ALL THE PARSING MAGIC HAPPENS
#####################################################################################
#####################################################################################
#####################################################################################

def match_input(input_list):

    # rather than excepting a bunch of errors
    # it is easier to just return if the input list is empty
    if input_list == []:
        return

    # VALUES THAT DONT HAVE OUTPUT SO THEY GO ABOVE THE PRINT STATEMENT
    match input_list[0]:
        case "clear":
            clear_terminal()
        case "exit":
            exit_gracefully()

# THESE KEPT HERE FOR LINE DEBUGGING WARRIORS

        case "debug":
            try:
                if input_list[1] == "user_table":
                    print(USER_TABLE)
                elif input_list[1] == "priv_key_table":
                    print(PRIV_KEY_TABLE)
                elif input_list[1] == "pub_key_table":
                    print(PUB_KEY_TABLE)
                elif input_list[1] == "password_list":
                    print(PASSWORD_LIST)
                elif input_list[1] == "password_directory":
                    print(PASSWORD_DIRECTORY)
            except:
                debug()

    # VALUES THAT HAVE OUTPUT ARE BELOW THE PRINT STATEMENT BECAUSE THEY NEED A SPACE
    print("")

    # GLOBAL OPTIONS FOR ALL USERS
    match input_list[0]:
        case "help":
            display_help()
        case "start":
            display_start()
        case "whoami":
            print(ACTIVE_USER)

    # OPTIONS FOR LOGGED OUT USERS
    if LOGGED_IN == False:
        match input_list[0]:
            case "register":
                try:
                    register_new_user()
                    FILE_MANAGER.write_all_files()
                except KeyboardInterrupt:
                    print ("\nRegistration cancelled.")
            case "login":
                try:
                    login_user()
                except KeyboardInterrupt:
                    print ("\nLogin cancelled.")
            case "passwd":
                logged_out_user_using_logged_in_command()           
            case "logout":
                logged_out_user_using_logged_in_command()
            case "add":
                logged_out_user_using_logged_in_command()
            case "view":
                logged_out_user_using_logged_in_command()
            case "reveal":
                logged_out_user_using_logged_in_command()
            case "delete":
                logged_out_user_using_logged_in_command()
            case "update":
                logged_out_user_using_logged_in_command()

    # OPTIONS FOR LOGGED IN USERS
    if LOGGED_IN == True:
        match input_list[0]:
            case "passwd":
                try:
                    change_user_password()
                    FILE_MANAGER.write_all_files()
                except KeyboardInterrupt:
                    print ("\nPassword change cancelled.")
            case "logout":
                logout_user()
            case "add":
                try:
                    create_password()
                    FILE_MANAGER.write_all_files()
                except KeyboardInterrupt:
                    print ("\nPassword creation cancelled.")
            case "view":
                show_passwords()
            case "reveal":
                try:
                    match input_list[1]:
                        case "all":
                            reveal_passwords()
                        case _:
                            reveal_password_uuid(input_list[1])
                    print("")
                    print("IMPORTANT!")
                    print("For security reasons, please clear your screen after revealing password data!")
                    print("To clear your screen use the 'clear' command")
                except:
                    reveal_instructions()
            case "delete":
                try:
                    match input_list[1]:
                        case _:
                            delete_password(input_list[1])
                            FILE_MANAGER.write_all_files
                except:
                    delete_instructions()
            case "update":
                try:
                    match input_list[1]:
                        case _:
                            try:
                                update_password(input_list[1]) 
                                FILE_MANAGER.write_all_files()
                            except KeyboardInterrupt:
                                print ("\nPassword update cancelled.")
                except:
                    update_instructions()
                

    # SPACE AFTER OUTPUT FOR CLARITY
    print("")

#####################################################################################
#####################################################################################
#####################################################################################
# THIS IS WHERE THE PROGRAM LOGIC BEGINS
#####################################################################################
#####################################################################################
#####################################################################################

# instantiate the file manager
FILE_MANAGER = FileManager()
# bootstrap any files that exist in the directory from previous sessions
FILE_MANAGER.bootstrap_files()

# load the splashscreen for the user
display_splashscreen()

# using a try here so that I can except KeyboardInterrupt
try:
    while True:

        # gather and match the input
        match_input(get_user_input())

# if the user presses ctrl+c, exit gracefully rather than making an ugly error message
except KeyboardInterrupt:
    exit_gracefully()
