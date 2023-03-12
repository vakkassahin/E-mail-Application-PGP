# Server Side (B)

import socket
import select
import time
import math
import random
import pyaes
import base64
import hashlib

HOST = 'localhost'
PORT = 65439

def main():
    # instantiate a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('socket instantiated')

    # bind the socket
    sock.bind((HOST, PORT))
    print('socket binded')

    # start the socket listening
    sock.listen(2)
    print('socket now listening')

    # accept the socket response from the client, and get the connection object
    conn, addr = sock.accept()      
    print('socket accepted, got connection object')
    
    while True:    
            
            # Client'tan gelen veriyi alıp değişkene atıyorum
	    data = conn.recv(10000)
	    encrypted_client_message = data.decode()
	    
	    # Önce aralarına virgül koyup birleştirdiğim RSA ile şifrelenmiş keyi ve AES le şifrelenmiş signed digest+mesajı ayırıyorum
	    splitted_encrypted_message = encrypted_client_message.split(',',1)
	    encrypted_key_str = str(splitted_encrypted_message[0])
	    encrypted_digest_plus_message = str(splitted_encrypted_message[1])
	    print('encrypted client key= '+encrypted_key_str,'\n')
	    
	    # Ayırdığım şifrelenmiş keyi, server'ın private keyi ile RSA algoritmasını kullanarak decryption yapıyorum   
	    p = 1001303203318050290393 
	    q = 1011235813471123581347 
	    n = p*q
	    phi = (p-1)*(q-1)	    
	    e = 9535859
	    d = inverse(e, phi)
	    client_e = 2868757
	    client_n = 974234969946798709856638624109350813312109
	    print('e= ',e,'\n')
	    print('d= ',d,'\n')
	    print('n= ',n,'\n')
	    int_encrypted_key_str = int(encrypted_key_str)
	    client_key = pow(int_encrypted_key_str,d, n)
	    print('decrypted client key= ',client_key,'\n')
	    
	    # Çözdüğüm keyi kullanarak AES decryption yapıyorum
	    bytes_val = client_key.to_bytes(16, 'big')
	    new_cipher=base64.b64decode(encrypted_digest_plus_message)
	    aes = pyaes.AESModeOfOperationCTR(bytes_val)
	    decrypted = aes.decrypt(new_cipher)
	    new_decrypted = str(decrypted,'UTF-8')
	    print ('decrypted edilen signed digest+mesaj= '+new_decrypted,'\n')
	    
	    # Signed digest ile mesajı ayırıyorum
	    splitted_digest_and_message = new_decrypted.split('.',1)
	    signed_digest = str(splitted_digest_and_message[0])	    
	    message = str(splitted_digest_and_message[1])
	    print('signed digest= '+signed_digest,'\n')
	    
	    # Signed digest'ı integer'a çevirmek için değişken tipini list yapıyorum
	    liste = list(signed_digest.split(" "))
	    int_signed_digest = []
	    for character in liste:
	    	int_signed_digest.append(int(character))
	    
	    # Signed digest'ı decryption yaparak mesajın hash'lenmiş halini elde ediyorum	
	    decyrpted_values = []
	    for character in int_signed_digest:
	    	decyrpted_values.append(pow(character, client_e, client_n))
	    ASCII_to_hex = []
	    for character in decyrpted_values:
	    	ASCII_to_hex.append(chr(character))
	    hash_values = []
	    hash_values = ' '.join(map(str, ASCII_to_hex))
	    hash_values = hash_values.replace(" ", "")
	    print('after decryption of signed digits= '+hash_values,'\n')
	    
	    # Mesajı hash algoritmasına sokuyorum
	    message_md5 = hashlib.md5(message.encode(encoding='UTF-8')).hexdigest()
	    print('mesajın hash algoritmasından sonraki hali= ',message_md5,'\n')
	    
	    # Mesajın hash'lenmiş hali ile signed digest'ın decryption yapılmış hali aynı mı diye bakıyorum. Eğer aynı ise mesaj doğru client'tan gelmiş demektir.
	    if hash_values == message_md5:
	    	print('Digest lar aynıdır. Dolayısıyla mesaj A client ından gelmiştir','\n')
	    	print('Client dan gelen mesaj: '+message,'\n')
	    else:
	    	print('Digestlar farklıdır. Dolayısıyla mesaj başka bir client tan gelmiştir!','\n')
	   
# end function

def inverse(e, phi):
    a, b, u = 0, phi, 1
    while(e > 0):
        q = b // e
        e, a, b, u = b % e, u, e, a-q*u
    if (b == 1):
        return a % phi
    else:
        print("Must be coprime!")

if __name__ == '__main__':
    main()
