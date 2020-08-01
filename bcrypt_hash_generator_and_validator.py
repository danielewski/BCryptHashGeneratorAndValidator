import bcrypt
import pyperclip


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


def generate_hash():
    byte_password = str.encode(input("Please enter phrase to hash: "))

    salt = bcrypt.gensalt()

    hashed_password = bcrypt.hashpw(byte_password, salt)

    if bcrypt.checkpw(byte_password, hashed_password):
        decoded_hashed_password = hashed_password.decode()
        pyperclip.copy(decoded_hashed_password)
        print("Success, Hashed password copied to clipboard: ", decoded_hashed_password, "\n")
    else:
        print("Error generating hash.\n")


def compare_hash():
    byte_password = str.encode(input("Please enter plaintext password: "))

    plaintext_hash = str.encode(input("please enter hash: "))

    if bcrypt.checkpw(byte_password, plaintext_hash):
        print("Password and hash match.\n")
    else:
        print("Password and hash do not match.\n")


while True:
    welcome_func()
