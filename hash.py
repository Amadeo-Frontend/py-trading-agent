from passlib.context import CryptContext

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
print(pwd.hash("Sop@rhiJ2026**"))


