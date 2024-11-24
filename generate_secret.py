import secrets
import string
from sys import argv

DEFAULT_SECRET_LENGTH = 64
DEFAULT_SECRET_NAME = "NEW_SECRET"


def generate_secret_string(length: int = DEFAULT_SECRET_LENGTH) -> str:
    punctuation = (
        string.punctuation.replace('"', "").replace("'", "").replace("=", "").replace(" ", "").replace("\\", "")
    )
    alphabet = string.ascii_letters + string.digits + punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


def write_secret_to_dotenv(secret_name: str = DEFAULT_SECRET_NAME, length=DEFAULT_SECRET_LENGTH) -> None:
    secret_string = generate_secret_string(length)
    with open(".env", "a") as file:
        file.write(f"""{secret_name}="{secret_string}"\n""")
    print(f"Secret '{secret_name}' written to .env")


if __name__ == "__main__":
    secret_name = argv[1] if len(argv) > 1 else DEFAULT_SECRET_NAME
    secret_length = int(argv[2]) if len(argv) > 2 else DEFAULT_SECRET_LENGTH
    write_secret_to_dotenv(secret_name, secret_length)
