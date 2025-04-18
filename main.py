import hashlib
import getpass
import os
import platform
import sys
import uuid

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding



print("Welcome to PyPass")
print("")
print("For a list of commands, type 'help'")

#global LOGGED_IN
#global USER_TABLE
#global PRIV_KEY_TABLE
#global PUB_KEY_TABLE
#global PASSWORD_LIST
#global PASSWORD_DIRECTORY
#global ACTIVE_USER

LOGGED_IN = False
USER_TABLE = {}
PRIV_KEY_TABLE = {}
PUB_KEY_TABLE = {}
PASSWORD_LIST = {}
PASSWORD_DIRECTORY = {}
ACTIVE_USER = "PyPass"

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
    print("  |  - passwd: changes your PyPass password              |")
    print("  |  - view: views all passwords                         |")
    print("  |  - add: adds a new password                          |")
    print("  |  - delete: deletes a password                        |")
    print("  |  - update: updates a password                        |")
    print("  |______________________________________________________|")
    print("")

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
# THISH FUNCTION CREATES A SHORTENED UUID FOR THE PASSWORD HASH TABLE INDEXES
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
    username_input = input(prompt)
    username_encoded = username_input.encode('utf-8')
    username_hash = hashlib.sha512(username_encoded).hexdigest()
    return (username_input, username_hash)


#####################################################################################
# THIS FUNCTION GETS THE PASSWORD FROM THE USER AND RETURNS A HASHED PASSWORD
# ARGS: prompt -> THE PROMPT TO DISPLAY TO THE USER
#####################################################################################

def get_password_from_user(prompt):
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
    def encrypt_data_encoded(data, public_key):
        encrypted_data = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        return encrypted_data
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
    bit_text = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
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
    for i in range(3):
        username = get_username_from_user("Username: ")
        password = get_password_from_user("Password: ")
        if login_check(username[1], password):
            print("Login successful!")
            global ACTIVE_USER
            ACTIVE_USER = username[0]
            global LOGGED_IN
            LOGGED_IN = True
            return
        elif i == 2:
            print("Login failed, 3 try limit reached")
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
        new_user_input = get_username_from_user("Enter a username: ")[1]

        # make sure the username is not already in the user table
        if new_user_input in USER_TABLE:
            return (new_user_input, False)
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

    try:
        assert new_user_input != None, "Username is None, this should not happen"
    except AssertionError as e:
        print(f"AssertionError: {e}")
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

        # adds in the format {username: password}
        USER_TABLE[new_user[0]] = new_user[1]

        # adds in the form {username: private_key}
        PRIV_KEY_TABLE[new_user[0]] = user_keys[1]

        # adds in the form {username: public_key}
        PUB_KEY_TABLE[new_user[0]] = user_keys[0]

        print("New user created successfully!")


#####################################################################################
# THIS FUNCTION CHANGES THE USER'S PASSWORD
#####################################################################################

def change_user_password():
    for i in range(3):
        old_password = get_password_from_user("Enter your old password: ")
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
            current_user_hash = hashlib.sha512(ACTIVE_USER.encode('utf-8')).hexdigest()
            encrypted_password = encrypt_data(password_input, PUB_KEY_TABLE[current_user_hash])
            encrypted_username = encrypt_data(username_input, PUB_KEY_TABLE[current_user_hash])
            uuid = uuid_short()
            PASSWORD_LIST[uuid] = (name_input, encrypted_username, encrypted_password)
            PASSWORD_DIRECTORY[uuid] = current_user_hash
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

    #AVOID NONE ERRORS
    if user_input == []:
        user_input = [""]

    #return the final user input after processing
    return user_input

def logout_user():
    global LOGGED_IN
    global ACTIVE_USER
    LOGGED_IN = False
    ACTIVE_USER = "PyPass"
    clear_terminal()


#####################################################################################
#####################################################################################
#####################################################################################
# THIS IS WHERE ALL THE PARSING MAGIC HAPPENS
#####################################################################################
#####################################################################################
#####################################################################################

def match_input(input_list):

    #global LOGGED_IN

    

    # VALUES THAT DONT HAVE OUTPUT SO THEY GO ABOVE THE PRINT STATEMENT
    match input_list[0]:
        case "":
            return
        case "clear":
            clear_terminal()
        case "exit":
            exit_gracefully()
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

    match input_list[0]:
        case "help":
            display_help()
        case "start":
            display_start()
        case "whoami":
            print(ACTIVE_USER)

    if LOGGED_IN == False:
        match input_list[0]:
            case "register":
                register_new_user()
            case "login":
                login_user()

    if LOGGED_IN == True:
        match input_list[0]:
            case "passwd":
                change_user_password()
            case "logout":
                logout_user()
            case "add":
                create_password()

    # SPACE AFTER OUTPUT FOR CLARITY
    print("")



#####################################################################################
#####################################################################################
#####################################################################################
# THIS IS WHERE THE PROGRAM LOGIC BEGINS
#####################################################################################
#####################################################################################
#####################################################################################

display_splashscreen()

# using a try here so that I can except KeyboardInterrupt
try:
    while True:

        # gather and match the input
        match_input(get_user_input())

# if the user presses ctrl+c, exit gracefully rather than making an ugly error message
except KeyboardInterrupt:
    exit_gracefully()
    
        



        
