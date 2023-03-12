# Client Side (A)

import socket
import select
import hashlib
import sys
import pyaes
import os
import base64

HOST = 'localhost'
PORT = 65439

def main():
    # instantiate a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('socket instantiated')

    # connect the socket
    connectionSuccessful = False
    while not connectionSuccessful:
        try:
            sock.connect((HOST, PORT))    
            print('socket connected','\n')
            connectionSuccessful = True
        except:
            pass
       
    message = input("Bir mesaj girin: ")
	  
    # md5 hash algoritması
    message_md5 = hashlib.md5(message.encode(encoding='UTF-8')).hexdigest()
	  
    print("The hexadecimal equivalent of hash is : "+ message_md5 +"\n")
    
    while True:
    
	    # RSA algoritması için gereken p, q, n, phi, e ve d değerlerini tanımlıyorum
	    p = 975319753197531975319
	    q = 998887766553300224411
	    n = p*q
	    phi = (p-1)*(q-1)
	    e = 2868757
	    d = inverse(e, phi)
	    print('e= ',e,'\n')
	    print('d= ',d,'\n')
	    print('n= ',n,'\n')
	    
	    # Mesajın hash'lenmiş halini ASCİİ değerlerine çeviriyorum
	    ASCII_values = []
	    for character in message_md5:
	    	ASCII_values.append(ord(character))
	    print('Mesajın ASCİİ değerleri= ',ASCII_values,'\n')
	    
	    # ASCİİ değerlerini A'nın private keyi ile şifreliyorum
	    rsa_values = []
	    for character in ASCII_values:
	    	rsa_values.append(pow(character,d, n))
	    print('ASCİİ değerlerin RSA ile encryption yapılmış hali= ',rsa_values,'\n')
	    
	    # Şifrelenmiş datayı stringe çeviriyorum
	    str_rsa_values = []
	    str_rsa_values = ' '.join(map(str, rsa_values))	
	    
	    # Signed digest ile mesajın arasına nokta koyup birleştiriyorum
	    message_plus_signed_digest= str_rsa_values+'.'+message
	    print('message+signed digest= '+message_plus_signed_digest,'\n')
	    
	    # AES algoritması için 16 byte'lık bir random key oluşturdum ve RSA ile şifreleyebilmek için integer'a çevirdim
	    key = os.urandom(16)
	    key_int = bytes_to_int(key)
	    print('AES algoritması keyi= ',key_int,'\n')
	    # AES'te kullandığım simetrik key'i, B nin yani server'ın public key'iyle RSA algoritması kullanarak şifreledim
	    servers_e=9535859
	    servers_n=1012553659338570434141874590808403508099371
	    rsa_key = pow(key_int,servers_e,servers_n)
	    print('RSA ile şifrelenmiş AES keyi= ',rsa_key,'\n')
	    string_rsa_key = str(rsa_key)
	    
	    # AES encryption yapıyorum ve şifrelenmiş mesaj anlamına gelen ciphertext'i elde ediyorum
	    aes = pyaes.AESModeOfOperationCTR(key)
	    ciphertext = aes.encrypt(message_plus_signed_digest)
	    
	    # Bytes tipinde olan ciphertext, direkt olarak UTF-8 formatına dönüşemediğinden, önce b64 encode'dan geçiyorum sonra UTF-8 string formatına dönüştürüyorum
	    b64_string = str(base64.b64encode(ciphertext),'utf-8')
	    print('AES ciphertext= '+b64_string,'\n')
	    
	    # B'nin public key'i ile şifrelenmiş AES key'i ve AES ile şifrelenmiş signed digest+mesajı B'ye yani servera yolluyorum
	    sendingto_server=string_rsa_key+','+b64_string
	    print('Server a gönderilecek veri= '+sendingto_server,'\n')
	    sendTextViaSocket(sendingto_server, sock)
	    break
	
# end function

def sendTextViaSocket(message, sock):
    # encode the text message
    encodedMessage = bytes(message, 'utf-8')

    # send the data via the socket to the server
    sock.sendall(encodedMessage)

    # receive acknowledgment from the server
    encodedAckText = sock.recv(10000)
    ackText = encodedAckText.decode('utf-8')

    # log if acknowledgment was successful
    if ackText == ACK_TEXT:
        print('server acknowledged reception of text')
    else:
        print('error: server has sent back ' + ackText)
    # end if

    return message
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

def bytes_to_int(bytes):
    result = 0
    for b in bytes:
        result = result * 256 + int(b)
    return result
    
def printDivisors(n) :
    i = 1
    while i <= n :
        if (n % i==0) :
            print('bölenler: ',i),
        i = i + 1
            
if __name__ == '__main__':
    main()
