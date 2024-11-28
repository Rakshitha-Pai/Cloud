from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives import serialization

private_key=ec.generate_private_key(ec.SECP256R1())

public_key=private_key.public_key()

public_pem=public_key.public_bytes(

encoding=serialization.Encoding.PEM,

format=serialization.PublicFormat.SubjectPublicKeyInfo)

print("public key pem format: \n",public_pem.decode())

message=input("enter a message to be signed:").encode()

signature=private_key.sign(message, ec. ECDSA(hashes.SHA256()))

print("signature", signature)

try:
     public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
     print("Signature is valid")
except:
    print("signature is failed")


this is last 7 th one single curve


2 )   def gcd(a,b):
    while b!=0:
        a,b=b,a%b
    return a
def modinv(e,phi):
    d,x1,x2,y1=0,0,1,1
    temp_phi=phi
    while e>0:
        temp1,temp2=divmod(temp_phi,e)
        temp_phi,e=e,temp2
        x=x2-temp1*x1
        y=d-temp1*y1
        x2,x2=x1,x
        d,y1=y1,y
    if temp_phi==1:
        return d+phi
def generate_key(p,q):
    n=p*q
    phi=(p-1)*(q-1)
    e=17
    g=gcd(e,phi)
    while g!=1:
        e+=1
        g=gcd(e,phi)
    d=modinv(e,phi)
    return((e,n),(d,n))
def encrypt(pk,plaintext):
    key,n=pk
    cipher=[pow(ord(char),key,n) for char in plaintext]
    return cipher
def decrypt(pk,ciphertext):
    key,n=pk
    plain=[chr(pow(char,key,n)) for char in ciphertext]
    return''.join(plain)
if __name__=='__main__':
    p=int(input("p:"))
    q=int(input("q:"))
    public,private=generate_key(p,q)
    print(f"public key:{public}")
    print(f"private key:{private}")
    message=input("mssg:")
    encryp_msg=encrypt(public,message)
    print(f"encrypted mssg:{encryp_msg}")
    dec_msg=decrypt(private,encryp_msg)
    print(f"dec mssg:{dec_msg}")






3).   def generate_public_key(prime, base, private_key):
    return pow(base, private_key, prime)

def generate_shared_secrete(public_key, private_key, prime):
    return pow(public_key, private_key, prime)

prime = int(input("enter a large prime number (recommended 2048 bits)"))
base = int(input("enter a base (primitive root modulo of prime)"))

alice_private = int(input("enter your private key (a random integer less than prime)"))
alice_public = generate_public_key(prime, base, alice_private)
print("Alice public key", alice_public)

bobs_private = int(input("enter your private key (a random integer less than prime)"))
bobs_public = generate_public_key(prime, base, bobs_private)
print("Bobs public key", bobs_public)

alice_shared = generate_shared_secrete(bobs_public, alice_private, prime)
bobs_shared = generate_shared_secrete(alice_public, bobs_private, prime)

print("Alice shared key", alice_shared)
print("Bobs shared key", bobs_shared)

if alice_shared == bobs_shared:
    print("Success the shared key is", alice_shared)
else:
    print("Error: shared key doesn't match")
