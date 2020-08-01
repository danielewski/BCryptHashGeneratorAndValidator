import bcrypt


def welcome_func():
    user_response = int(
        input("Please enter \"1\" to generate a new hash, \"2\" to compare a password with a hash, \"0\" to exit."))

    if user_response == 1:
        generate_hash()
    elif user_response == 2:
        compare_hash()
    elif user_response == 0:
        quit()
    else:
        print("Invalid input.")
        welcome_func()


def generate_hash():
    plaintext_phrase = input("Please enter phrase to hash: ")

    byte_password = str.encode(plaintext_phrase)

    salt = bcrypt.gensalt()

    hashed_password = bcrypt.hashpw(byte_password, salt)

    if bcrypt.checkpw(byte_password, hashed_password):
        print("Success, Hashed password: " + hashed_password.decode())
    else:
        print("Error generating hash.")
    welcome_func()


def compare_hash():
    plaintext_phrase = input("Please enter plaintext password: ")

    byte_phrase = str.encode(plaintext_phrase)

    plaintext_hash = str.encode(input("please enter hash: "))

    if bcrypt.checkpw(byte_phrase, plaintext_hash):
        print("Password and hash match")
    else:
        print("Password and hash do not match")
    welcome_func()


welcome_func()
