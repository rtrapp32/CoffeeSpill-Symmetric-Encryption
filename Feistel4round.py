import hashlib
import os
import json
#we declare a list that will be used later to hold the keylist
keyList = []

#This function hashes the key to get a standard length key reguardless of password, Important for splitting
def HashMe(toBeHashed):
    # We create the HashMe function which hases any input given to it.
    # We will reuse this funciton later
    # we pass an Argument into this funciton caled toBeHashed which is a string
    # The string is converted into a bytestring below so that hasing operatons
    # can happen with it
    MakeItByte = bytes(toBeHashed,'utf-8')
    #now we hash the byteArray using sha256
    HashedBoi = hashlib.sha512(MakeItByte).digest()
    #hashedBoi stores the hashed output as binary
    #then below we print it to ensure that we are properly hashing.
    #Hex digest is needed to display binary for humans.the below line 
    # was used to verify that the input is being hashed properly
    #now we return the hashed input for use.

    return HashedBoi

#This function checks if the Plaintest is odd or even since this is a xymetric feistel cipher. 
#if it is odd, padding will be added to the end of the PT before encryption
def PlaintextOddFix(PlainTextIn):
    # Gets length of plaintext
    PlainTextLen = len(PlainTextIn)
    #below is a Modulo which checks if the string is odd or even, then actually does the
    #append and returns a value
    if PlainTextLen & 1:
        #if the last bit is set, it is Odd
        #if it is odd, we append a hash of the length of the PT and our fixed hash ending in $ 
        
        PTLength = str(len(PlainTextIn) + 33 )
        toBeHashed = (PTLength + "009cb9f1e3305cc28214366b4fed0e5c6871e9ed5345c17a7faa65f3c47a3df2$")
        MakeItByte = bytes(toBeHashed,'utf-8')
        HashedBoi = hashlib.sha256(MakeItByte).digest()
        #after hashing the PTLength and the Hash string, we hash that with MD% to shortenit. We Still hash the MSG length using a better hash
        #because that could be attacked for Cryptanalysis related informaiton
        HashedBoi = hashlib.md5(HashedBoi).hexdigest()
        PlainTextFix = PlainTextIn + HashedBoi + "$"
        return PlainTextFix

    else:
        #if last bit is not set, it is even and nothing needs to be done, we return the varible as we were given it
        return PlainTextIn


#this functin breaks the hashed key into subkeys
def KeyDivision(key):
    #in this fucntion we devide the SHA 512 key by 4 so that it can be used throughout the rounds eg k1, k2, k3, k4. This will be stored 
    #in a list so that it can be iterated through. The effective key length is 128 bits.
    keyhalf1, keyhalf2 = key[:len(key)//2], key[len(key)//2:]
    k1, k2 = keyhalf1[:len(keyhalf1)//2], keyhalf1[len(keyhalf1)//2:]
    k3, k4 = keyhalf2[:len(keyhalf2)//2], keyhalf2[len(keyhalf2)//2:]    
    keyList = [k1,k2,k3,k4]
    return keyList   

# we need a function that can XOR byte arrays
def xor_bytes (b1, b2):
    #b1 and b2 are our byte arrays we will XOR in this funciton
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])


def EncryptionRounds(Merged, keyList1):
    #first we find the total length of MergedKeyAndPT
    #then we devide it by 2, so we know how much of each ByteArray to take as each half
    half1, half2 = Merged[:len(Merged)//2], Merged[len(Merged)//2:]
    #for every key in the list we will do an encryption round
    #first we append the key section = to the round we are on to half2,
    # we store this as TempHalf2 becasue half 2 is preserved to the next round
    TempHalf2 =  (half2 + keyList1[0])
    #now we hash TempHalf 2
    TempHalf2 = hashlib.sha512(TempHalf2).digest()
    #now we XOR half1 against tempHalf2
    half1 = xor_bytes(half1, TempHalf2)
    #now we do the next round, round 2 which creates an encrypted half 2
    TempHalf1 =  (half1 + keyList1[1])
    #now we hash TempHalf 1
    TempHalf1 = hashlib.sha512(TempHalf1).digest()
    #now we XOR half1 against tempHalf2
    half2 = xor_bytes(TempHalf1, half2)
    #Another round, round 3
    TempHalf2 =  (half2 + keyList1[2])
    #now we hash TempHalf 2
    TempHalf2 = hashlib.sha512(TempHalf2).digest()
    #now we XOR half1 against tempHalf2
    half1 = xor_bytes(half1, TempHalf2)
    #now we do round 4
    TempHalf1 =  (half1 + keyList1[3])
        #now we hash TempHalf 1
    TempHalf1 = hashlib.sha512(TempHalf1).digest()
    #now we XOR half1 against tempHalf2
    half2 = xor_bytes(TempHalf1, half2)
    ciphertext = b"".join([half1,half2])
    return ciphertext
    
    
    
    
def DecryptionRounds(Merged, keyList1):
    #first split the ciphertext
    half1, half2 = Merged[:len(Merged)//2], Merged[len(Merged)//2:]
    #DECRYPT BELOW first we decrypt half2, then half 1
    TempHalf1 =  (half1 + keyList1[3])
        #now we hash TempHalf 1
    TempHalf1 = hashlib.sha512(TempHalf1).digest()
    #now we XOR half1 against tempHalf2
    half2 = xor_bytes(TempHalf1, half2)
    #now we decrypt half 1
    TempHalf2 =  (half2 + keyList1[2])
    #now we hash TempHalf 2
    TempHalf2 = hashlib.sha512(TempHalf2).digest()
    #now we XOR half1 against tempHalf2
    half1 = xor_bytes(half1, TempHalf2)
    #another round, decrypt half 2
    TempHalf1 =  (half1 + keyList1[1])
        #now we hash TempHalf 1
    TempHalf1 = hashlib.sha512(TempHalf1).digest()
    #now we XOR half1 against tempHalf2
    half2 = xor_bytes(TempHalf1, half2)
    #another round, decrypt half 1
    TempHalf2 =  (half2 + keyList1[0])
    #now we hash TempHalf 2
    TempHalf2 = hashlib.sha512(TempHalf2).digest()
    #now we XOR half1 against tempHalf2
    half1 = xor_bytes(half1, TempHalf2)
    #we join the halves
    plaintext = b"".join([half1,half2])
    #return the decrypted text
    return plaintext

def OutputPaddingFix(PlainTextIn):
    # Gets last 33 char of plaintext
    PlainTextLast = PlainTextIn[len(PlainTextIn)-33:]
    #We generate what the padding of the message was and see if that occurs in the PT.
    #the padding should be a SHA-256 hashed length of the message + 009cb9f1e3305cc28214366b4fed0e5c6871e9ed5345c17a7faa65f3c47a3df2$
    # and the money symbol at the end of the padding $
    PTLength = str(len(PlainTextIn))
    toBeHashed = (PTLength + "009cb9f1e3305cc28214366b4fed0e5c6871e9ed5345c17a7faa65f3c47a3df2$")
    #now we hash the length + 009cb9f1e3305cc28214366b4fed0e5c6871e9ed5345c17a7faa65f3c47a3df2$
    MakeItByte = bytes(toBeHashed,'utf-8')
    HashedBoi = hashlib.sha256(MakeItByte).digest()
    #Now we hash that to create the new shortened padding format
    HashedBoi = hashlib.md5(HashedBoi).hexdigest()
    #now we append $ and see if its the last 65 characters of our PT
    PlainTextPad = HashedBoi + "$"

    if PlainTextLast == PlainTextPad:
        #if last char = padding char, we remove it by finding the length of the string
        PlainTextLen = len(PlainTextIn)
        #then we remove the padding, since 33 is the amount of apdding chars, we remove 65
        PlainTextFix = PlainTextIn[:len(PlainTextIn) - 33]
        
        return PlainTextFix

    else:
        #if it is not our reserved padding, no padding iz present, so we can return
        return PlainTextIn


def EncryptMode(PlainText, PlainKey):
    #we hash the key so it is a uniform 512 bits reguardless of whatever the user makes the key
    HashedKey = HashMe(PlainKey)
    #we devide the key into 4 128 bit subkeys
    keyList = KeyDivision(HashedKey)
    #now we make the PlainText Even. We make it even because the Feistel cipher is symetric. 
    # The PlainText is now stored as NewPT and its length is even
    PTchunks = chunker(PlainText)
    #we make an empty list to hold the chunks of CT
    CTList = []
    for NewPT in PTchunks:
        BytesText = bytes(NewPT, 'utf-8')
        # we feed the encryption round bytestext and a key list so that encryption can occur
        CipherText = EncryptionRounds(BytesText, keyList)
        
        #below the CipherText is returned
        CTList.append(CipherText)

    return CTList

def DecryptMode(CipherText, PlainKey):
    #we hash the key so it is a uniform 512 bits reguardless of whatever the user makes the key
    HashedKey = HashMe(PlainKey)
    #we devide the key into 4 128 bit subkeys, which we use to decrypt
    keyList = KeyDivision(HashedKey)
    #now we decrypt
    PT = DecryptionRounds(CipherText, keyList)
    #now we convert the byte string to an ordinary string. 
    HumanPT = str(PT, 'UTF-8')
    #now we remove the padding characters if present, because it is merely padding
    HumanPT = OutputPaddingFix(HumanPT)
    
    return HumanPT

def ChunkyDecrypt(CipherText, PlainKey):
    #this function takes a list of CT and iterates through it.
    #The PT List holds the PlainText
    PT = []
    for CT in CipherText:
        #we decrypt the chunk
        DecryptedChunk = DecryptMode(CT, PlainKey)
        #then append it to the PT list
        PT.append(DecryptedChunk)
    #then we return the PT
    return PT

def OutputToFile(OutText, StandardText):
    #this funciton gets a filename and writes "Outtext" contents to the file in either JSON or stnadard Text. OutText Can only be Strings
    #First we get a filename
    Outfile = input("Please enter a FileName for your output: ")
    #Then we evaluate whether or not JSON, or Human text is desired.
    if StandardText:
        #here we join up entries from the PlainText List and write it
        #first we create one long string from the Outtext
        OutText = ''.join(OutText)

        try:
            outputTextFile = open(Outfile, "x")
            #using the writelines() funciton the /n creates a new line, which preserves the formatting of input text
            outputTextFile.writelines(OutText)
        except:
            outputTextFile = open(Outfile, "w")
            outputTextFile.writelines(OutText)
    else:
        #first, OutText is a List of chunks. This list is converted to JSON
        OutJson = json.dumps(OutText)
        
        #below we check if outputTextFile exists, create the file if it doesnt exist, then write to it.
        try:
            outputTextFile = open(Outfile, "x")
            outputTextFile.write(OutJson)
        except:
            outputTextFile = open(Outfile, "w")
            outputTextFile.write(OutJson)

def chunker(PlainText):
    
    #this function cuts the plaintext into 256 bit chunks and then returns the bits as a List.
    #First we set the Chunk Size (In characters) in a varible. Sionce we are using UTF-8 each character can be up to 4 bits and 4*64 = 256.
    ChunkSize = 64
    #now we Oddfix the data to ensure that it is even
    PlainText = PlaintextOddFix(PlainText)
    #now we actually break it into chunks
    chunks = [PlainText[i:i+ChunkSize] for i in range(0, len(PlainText), ChunkSize)]
    return chunks
    
def CTListHexify(CTList):
    #this funciton converts Lists of bitstrings into lists of hex strings
    HexCTList = []
    for CT in CTList:
        #we iterate through the list of CT byte strings and convert them to Hex
        #the hex is appended to HexCTList
        HexCTList.append(CT.hex())
    #hexCTList is returned by this funciton. Hex CT list containt the CipherText as standard Strings.
    return HexCTList
        
def ChunkFileLoad(Infile):
    #This function loads a File containing cipherText JSON information, and converts it into a list which is returned as
    #PlainBytesList. 
    inputText = open( Infile, "r")
    PlainTextList = json.load(inputText)
    PlainBytesList = []
    #using this forloop we iterate through every chunk in the Plaintext list. 
    for chunk in PlainTextList:
        #the data from the chunk is loaded, and converted to bytestrings
        PlainText = bytes.fromhex(chunk)
        #the bytestrings are saved to a list called PlainBytes list
        PlainBytesList.append(PlainText)
    #the PlainBytesList is returned
    return PlainBytesList


def Main():
    #this is our main funciton which calls other funcitons.
    Mode = input("Do you want to (E)ncrypt Or (D)ecrypt? : ")

    if Mode == "E":
        InputType = input("Do you want to use a (F)ile or a (S)tring? : ")
        if InputType == "F":
            #if the user entered F, they want to use a file, so we need a filename to look for
            Infile = input("Please enter a FileName: ")
            #we open the users filename
            inputText = open( Infile , "r")
            #we read the file and use it as out Plaintext
            PlainText = inputText.read()
            #now we get a key with which we will encrypt
            PlainKey = input("Please enter a key: ")
            #now we split the Plaintext into chunks
            chunker(PlainText)
            #now we do actual encryption
            CT = EncryptMode(PlainText, PlainKey)
            #Now we convert the ByteString to Hexfor Storage
            CT = CTListHexify(CT)
            #since we want to store as JSON, Standard text = False
            StandardText = False
            OutputToFile(CT, StandardText)

        elif InputType == "S":
            PlainText = input("Please Input a String to be encrypted: ")
            PlainKey = input("Please enter a key: ")
            CT = EncryptMode(PlainText, PlainKey)
            #Now we convert the ByteString to Hex for storage
            CT = CTListHexify(CT)
            #since we want to store as JSON, Standard text = False
            StandardText = False
            OutputToFile(CT, StandardText)
        else:
            print("Invalid Selection, please input F for File or S for String")

    elif Mode == "D":
        Infile = input("Please enter a FileName: ")
        #First we load the file full of chunks
        PlainText = ChunkFileLoad(Infile)
        #then we get the key
        PlainKey = input("Please enter a key: ")
        #then we pass the key and List of plaintext to a function that iterates through and decrypts chunk by chunk
        PT = ChunkyDecrypt(PlainText, PlainKey)
        #we ask if they want to save PT to file
        KeepInFile = input("Would you like to save your output Y/N?")
        if KeepInFile == "Y":
            #Set standard Text to True which Tells the output to file function to store the text in a human form, not JSON.
            StandardText = True
            OutputToFile(PT, StandardText)
        elif KeepInFile == "N":
            print(PT)

    else:
        print("Invalid Selection, please input E for Encrypt or D for Decrypt")


Main()
