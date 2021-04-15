#Mizogg.co.uk 12/03/21 ProjectHex (256Dec Scanner)
#Install all Modules
#pip3 install bit chainside-btcpy eth_keys eth-hash[pycryptodome]
import random
from decimal import *
from bit import *
from bit.format import bytes_to_wif
from binascii import hexlify
import eth_keys
from eth_keys import keys
from btcpy.structs.crypto import PublicKey
from btcpy.structs.address import P2wpkhAddress #,P2pkhAddress
import multiprocessing
from multiprocessing import Pool
import atexit
from time import time
from datetime import timedelta, datetime


def seconds_to_str(elapsed=None):
    if elapsed is None:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    else:
        return str(timedelta(seconds=elapsed))


def log(txt, elapsed=None):
    colour_cyan = '\033[36m'
    colour_reset = '\033[0;0;39m'
    colour_red = '\033[31m'
    print('\n ' + colour_cyan + '  [TIMING]> [' + seconds_to_str() + '] ----> ' + txt + '\n' + colour_reset)
    if elapsed:
        print("\n " + colour_red + " [TIMING]> Elapsed time ==> " + elapsed + "\n" + colour_reset)


def end_log():
    end = time()
    elapsed = end-start
    log("End Program", seconds_to_str(elapsed))


start = time()
atexit.register(end_log)
log("Start Program")

print("Loading Address List Please Wait and Good Luck...")
with open("biglist.txt","r") as m: #Your Address List mix of addresses
    add = m.read().split()
add= set(add)

r = 0
cores=1

def seek(r):
    while True:
        c1 = str (random.choice("01"))
        c2 = str (random.choice("01"))
        c3 = str (random.choice("01"))
        c4 = str (random.choice("01"))
        c5 = str (random.choice("01"))
        c6 = str (random.choice("01"))
        c7 = str (random.choice("01"))
        c8 = str (random.choice("01"))      
        c9 = str (random.choice("01"))
        c10 = str (random.choice("01"))
        c11 = str (random.choice("01"))
        c12 = str (random.choice("01"))
        c13 = str (random.choice("01"))
        c14 = str (random.choice("01"))
        c15 = str (random.choice("01"))
        c16 = str (random.choice("01"))
        c17 = str (random.choice("01"))
        c18 = str (random.choice("01"))
        c19 = str (random.choice("01"))
        c20 = str (random.choice("01"))
        c21 = str (random.choice("01"))
        c22 = str (random.choice("01"))
        c23 = str (random.choice("01"))
        c24 = str (random.choice("01"))
        c25 = str (random.choice("01"))
        c26 = str (random.choice("01"))
        c27 = str (random.choice("01"))
        c28 = str (random.choice("01"))
        c29 = str (random.choice("01"))
        c30 = str (random.choice("01"))
        c31 = str (random.choice("01"))
        c32 = str (random.choice("01"))
        c33 = str (random.choice("01"))
        c34 = str (random.choice("01"))
        c35 = str (random.choice("01"))
        c36 = str (random.choice("01"))
        c37 = str (random.choice("01"))
        c38 = str (random.choice("01"))
        c39 = str (random.choice("01"))
        c40 = str (random.choice("01"))
        c41 = str (random.choice("01"))
        c42 = str (random.choice("01"))
        c43 = str (random.choice("01"))
        c44 = str (random.choice("01"))
        c45 = str (random.choice("01"))
        c46 = str (random.choice("01"))
        c47 = str (random.choice("01"))
        c48 = str (random.choice("01"))
        c49 = str (random.choice("01"))
        c50 = str (random.choice("01"))
        c51 = str (random.choice("01"))
        c52 = str (random.choice("01"))
        c53 = str (random.choice("01"))
        c54 = str (random.choice("01"))
        c55 = str (random.choice("01"))
        c56 = str (random.choice("01"))
        c57 = str (random.choice("01"))
        c58 = str (random.choice("01"))
        c59 = str (random.choice("01"))
        c60 = str (random.choice("01"))
        c61 = str (random.choice("01"))
        c62 = str (random.choice("01"))
        c63 = str (random.choice("01"))
        c64 = str (random.choice("01"))
        c65 = str (random.choice("01"))
        c66 = str (random.choice("01"))
        c67 = str (random.choice("01"))
        c68 = str (random.choice("01"))
        c69 = str (random.choice("01"))
        c70 = str (random.choice("01"))
        c71 = str (random.choice("01"))
        c72 = str (random.choice("01"))
        c73 = str (random.choice("01"))
        c74 = str (random.choice("01"))
        c75 = str (random.choice("01"))
        c76 = str (random.choice("01"))
        c77 = str (random.choice("01"))
        c78 = str (random.choice("01"))
        c79 = str (random.choice("01"))
        c80 = str (random.choice("01"))
        c81 = str (random.choice("01"))
        c82 = str (random.choice("01"))
        c83 = str (random.choice("01"))
        c84 = str (random.choice("01"))
        c85 = str (random.choice("01"))
        c86 = str (random.choice("01"))
        c87 = str (random.choice("01"))
        c88 = str (random.choice("01"))
        c89 = str (random.choice("01"))
        c90 = str (random.choice("01"))
        c91 = str (random.choice("01"))
        c92 = str (random.choice("01"))
        c93 = str (random.choice("01"))
        c94 = str (random.choice("01"))
        c95 = str (random.choice("01"))
        c96 = str (random.choice("01"))
        c97 = str (random.choice("01"))
        c98 = str (random.choice("01"))
        c99 = str (random.choice("01"))
        c100 = str (random.choice("01"))
        c101 = str (random.choice("01"))
        c102 = str (random.choice("01"))
        c103 = str (random.choice("01"))
        c104 = str (random.choice("01"))
        c105 = str (random.choice("01"))
        c106 = str (random.choice("01"))
        c107 = str (random.choice("01"))
        c108 = str (random.choice("01"))
        c109 = str (random.choice("01"))
        c110 = str (random.choice("01"))
        c111 = str (random.choice("01"))
        c112 = str (random.choice("01"))
        c113 = str (random.choice("01"))
        c114 = str (random.choice("01"))
        c115 = str (random.choice("01"))
        c116 = str (random.choice("01"))
        c117 = str (random.choice("01"))
        c118 = str (random.choice("01"))
        c119 = str (random.choice("01"))
        c120 = str (random.choice("01"))
        c121 = str (random.choice("01"))
        c122 = str (random.choice("01"))
        c123 = str (random.choice("01"))
        c124 = str (random.choice("01"))
        c125 = str (random.choice("01"))
        c126 = str (random.choice("01"))
        c127 = str (random.choice("01"))
        c128 = str (random.choice("01"))
        c129 = str (random.choice("01"))
        c130 = str (random.choice("01"))
        c131 = str (random.choice("01"))
        c132 = str (random.choice("01"))
        c133 = str (random.choice("01"))
        c134 = str (random.choice("01"))
        c135 = str (random.choice("01"))
        c136 = str (random.choice("01"))
        c137 = str (random.choice("01"))
        c138 = str (random.choice("01"))
        c139 = str (random.choice("01"))
        c140 = str (random.choice("01"))
        c141 = str (random.choice("01"))
        c142 = str (random.choice("01"))
        c143 = str (random.choice("01"))
        c144 = str (random.choice("01"))
        c145 = str (random.choice("01"))
        c146 = str (random.choice("01"))
        c147 = str (random.choice("01"))
        c148 = str (random.choice("01"))
        c149 = str (random.choice("01"))
        c150 = str (random.choice("01"))
        c151 = str (random.choice("01"))
        c152 = str (random.choice("01"))
        c153 = str (random.choice("01"))
        c154 = str (random.choice("01"))
        c155 = str (random.choice("01"))
        c156 = str (random.choice("01"))
        c157 = str (random.choice("01"))
        c158 = str (random.choice("01"))
        c159 = str (random.choice("01"))
        c160 = str (random.choice("01"))
        c161 = str (random.choice("01"))
        c162 = str (random.choice("01"))
        c163 = str (random.choice("01"))
        c164 = str (random.choice("01"))
        c165 = str (random.choice("01"))
        c166 = str (random.choice("01"))
        c167 = str (random.choice("01"))
        c168 = str (random.choice("01"))
        c169 = str (random.choice("01"))
        c170 = str (random.choice("01"))
        c171 = str (random.choice("01"))
        c172 = str (random.choice("01"))
        c173 = str (random.choice("01"))
        c174 = str (random.choice("01"))
        c175 = str (random.choice("01"))
        c176 = str (random.choice("01"))
        c177 = str (random.choice("01"))
        c178 = str (random.choice("01"))
        c179 = str (random.choice("01"))
        c180 = str (random.choice("01"))
        c181 = str (random.choice("01"))
        c182 = str (random.choice("01"))
        c183 = str (random.choice("01"))
        c184 = str (random.choice("01"))
        c185 = str (random.choice("01"))
        c186 = str (random.choice("01"))
        c187 = str (random.choice("01"))
        c188 = str (random.choice("01"))
        c189 = str (random.choice("01"))
        c190 = str (random.choice("01"))
        c191 = str (random.choice("01"))
        c192 = str (random.choice("01"))
        c193 = str (random.choice("01"))
        c194 = str (random.choice("01"))
        c195 = str (random.choice("01"))
        c196 = str (random.choice("01"))
        c197 = str (random.choice("01"))
        c198 = str (random.choice("01"))
        c199 = str (random.choice("01"))
        c200 = str (random.choice("01"))
        c201 = str (random.choice("01"))
        c202 = str (random.choice("01"))
        c203 = str (random.choice("01"))
        c204 = str (random.choice("01"))
        c205 = str (random.choice("01"))
        c206 = str (random.choice("01"))
        c207 = str (random.choice("01"))
        c208 = str (random.choice("01"))
        c209 = str (random.choice("01"))
        c210 = str (random.choice("01"))
        c211 = str (random.choice("01"))
        c212 = str (random.choice("01"))
        c213 = str (random.choice("01"))
        c214 = str (random.choice("01"))
        c215 = str (random.choice("01"))
        c216 = str (random.choice("01"))
        c217 = str (random.choice("01"))
        c218 = str (random.choice("01"))
        c219 = str (random.choice("01"))
        c220 = str (random.choice("01"))
        c221 = str (random.choice("01"))
        c222 = str (random.choice("01"))
        c223 = str (random.choice("01"))
        c224 = str (random.choice("01"))
        c225 = str (random.choice("01"))
        c226 = str (random.choice("01"))
        c227 = str (random.choice("01"))
        c228 = str (random.choice("01"))
        c229 = str (random.choice("01"))
        c230 = str (random.choice("01"))
        c231 = str (random.choice("01"))
        c232 = str (random.choice("01"))
        c233 = str (random.choice("01"))
        c234 = str (random.choice("01"))
        c235 = str (random.choice("01"))
        c236 = str (random.choice("01"))
        c237 = str (random.choice("01"))
        c238 = str (random.choice("01"))
        c239 = str (random.choice("01"))
        c240 = str (random.choice("01"))
        c241 = str (random.choice("01"))
        c242 = str (random.choice("01"))
        c243 = str (random.choice("01"))
        c244 = str (random.choice("01"))
        c245 = str (random.choice("01"))
        c246 = str (random.choice("01"))
        c247 = str (random.choice("01"))
        c248 = str (random.choice("01"))
        c249 = str (random.choice("01"))
        c250 = str (random.choice("01"))
        c251 = str (random.choice("01"))
        c252 = str (random.choice("01"))
        c253 = str (random.choice("01"))
        c254 = str (random.choice("01"))
        c255 = str (random.choice("01"))
        c256 = str (random.choice("01"))
		
        magic = (c1+c2+c3+c4+c5+c6+c7+c8+c9+c10+c11+c12+c13+c14+c15+c16+c17+c18+c19+c20+c21+c22+c23+c24+c25+c26+c27+c28+c29+c30+c31+c32+c33+c34+c35+c36+c37+c38+c39+c40+c41+c42+c43+c44+c45+c46+c47+c48+c49+c50
		+c51+c52+c53+c54+c55+c56+c57+c58+c59+c60+c61+c62+c63+c64+c65+c66+c67+c68+c69+c70+c71+c72+c73+c74+c75+c76+c77+c78+c79+c80+c81+c82+c83+c84+c85+c86+c87+c88+c89+c90+c91+c92+c93+c94+c95+c96+c97+c98+c99+c100
		+c101+c102+c103+c104+c105+c106+c107+c108+c109+c110+c111+c112+c113+c114+c115+c116+c117+c118+c119+c120+c121+c122+c123+c124+c125+c126+c127+c128+c129+c130+c131+c132+c133+c134+c135+c136+c137+c138+c139+c140+c141
		+c142+c143+c144+c145+c146+c147+c148+c149+c150+c151+c152+c153+c154+c155+c156+c157+c158+c159+c160+c161+c162+c163+c164+c165+c166+c167+c168+c169+c170+c171+c172+c173+c174+c175+c176+c177+c178+c179+c180+c181+c182+c183
		+c184+c185+c186+c187+c188+c189+c190+c191+c192+c193+c194+c195+c196+c197+c198+c199+c200+c201+c202+c203+c204+c205+c206+c207+c208+c209+c210+c211+c212+c213+c214+c215+c216+c217+c218+c219+c220+c221+c222+c223+c224+c225+c226
		+c227+c228+c229+c230+c231+c232+c233+c234+c235+c236+c237+c238+c239+c240+c241+c242+c243+c244+c245+c246+c247+c248+c249+c250+c251+c252+c253+c254+c255+c256)
        dec = int(magic,2)
        key1 = Key.from_int(dec)
        wif = bytes_to_wif(key1.to_bytes(), compressed=False) #Uncompressed WIF
        wif2 = bytes_to_wif(key1.to_bytes(), compressed=True) #compressed WIF
        key2 = Key(wif)
        caddr = key1.address											#Legacy compressed address
        uaddr = key2.address											#Legacy uncompressed address
        saddr = key1.segwit_address
        pub1 = hexlify(key1.public_key).decode()
        pub2 = hexlify(key2.public_key).decode()
        pubk1 = PublicKey.unhexlify(pub1)
        pubk2 = PublicKey.unhexlify(pub2)
        bcaddr = P2wpkhAddress(pubk1.hash(), version=0, mainnet=True)	#Segwit (bech32) compressed address
        buaddr = P2wpkhAddress(pubk2.hash(), version=0, mainnet=True)	#Segwit (bech32) uncompressed address
        myhex = "%064x" % dec
        private_key = myhex[:64]
        private_key_bytes = bytes.fromhex(private_key)
        public_key_hex = keys.PrivateKey(private_key_bytes).public_key
        public_key_bytes = bytes.fromhex(str(public_key_hex)[2:])
        eaddr = keys.PublicKey(public_key_bytes).to_address()           #Eth address
        if caddr in add:
            print ("Nice One Found!!!",dec, caddr, wif2, private_key) #Legacy compressed address
            s1 = str(dec)
            s2 = caddr
            s3 = wif2
            s4 = private_key
            f=open(u"CompressedWinner.txt","a") #Output File of Legacy compressed Wallet Found
            f.write(s1+":"+s2+":"+s3+":"+s4)
            f.write("\n")
            f.close()
            break #break or continue
        if uaddr in add:
            print ("Nice One Found!!!",dec, uaddr, wif, private_key) #Legacy uncompressed address
            s1 = str(dec)
            s2 = uaddr
            s3 = wif
            s4 = private_key
            f=open(u"UncompressedWinner.txt","a") #Output File of Legacy uncompressed Wallet Found
            f.write(s1+":"+s2+":"+s3+":"+s4)
            f.write("\n")
            f.close()
            break #break or continue
        if saddr in add:
            print ("Nice One Found!!!",dec, saddr, wif, private_key) #Segwit address
            s1 = str(dec)
            s2 = saddr
            s3 = wif
            s4 = private_key
            f=open(u"Winner3.txt","a") #Output File of Segwit Wallet Found
            f.write(s1+":"+s2+":"+s3+":"+s4)
            f.write("\n")                
            f.close()
            break #break or continue
        if str(bcaddr) in add:
            print ("Nice One Found!!!",dec, str(bcaddr)) #Segwit (bech32) compressed address
            s1 = str(dec)
            s2 = str(bcaddr)
            s3 = wif
            s4 = private_key
            f=open(u"bech32CompressedWinner.txt","a") #Output File of Segwit (bech32) compressed Wallet Found
            f.write(s1+":"+s2+":"+s3+":"+s4) 
            f.write("\n")                
            f.close()
            break #break or continue
        if str(buaddr) in add:
            print ("Nice One Found!!!",dec, str(buaddr)) #Segwit (bech32) uncompressed address
            s1 = str(dec)
            s2 = str(buaddr)
            s3 = wif
            s4 = private_key
            f=open(u"bechUncompressedWinner.txt","a") #Output File of Segwit (bech32) uncompressed Wallet Found
            f.write(s1+":"+s2+":"+s3+":"+s4) 
            f.write("\n")
            f.close()
            break #break or continue
        if eaddr in add:
            print ("Nice One Found!!!",dec, private_key, eaddr) #Eth address
            s1 = str(dec)
            s2 = eaddr
            s3 = wif
            s4 = private_key
            f=open(u"EthWinner.txt","a") #Output File of Eth Wallet Found
            f.write(s1+":"+s2+":"+s3+":"+s4) 
            f.write("\n")
            f.close()
            break #break or continue
        else:
            colour_cyan = '\033[36m'
            colour_reset = '\033[0;0;39m'
            colour_red = '\033[31m'
            print ("\n " + colour_cyan + "ProjectHex---" + colour_red + "---Good--Luck--Happy--Hunting--Mizogg.co.uk&Chad---" + colour_cyan + "---ProjectHex"  + colour_reset) # Running Display Output
            print (myhex)
            print (caddr)
            print (uaddr)
            print (saddr)
            print (bcaddr)
            print (buaddr)
            print (eaddr)
            print(colour_cyan + seconds_to_str())
#CPU Control Command
if __name__ == '__main__':
        jobs = []
        for r in range(cores):
                p = multiprocessing.Process(target=seek, args=(r,))
                jobs.append(p)
                p.start()