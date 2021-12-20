# Laboratorijske vježbe (SRP)

## 1. laboratorijske vježbe

12.10.2021.

## Zadatak

Realizirati man in the middle napad iskorištavanjem ranjivosti ARP protokola.

Student će testirati napad u virtualiziranoj Docker mreži (Docker container networking) koju čine 3 virtualizirana Docker računala (eng. container): 

1. station-1 
2. station-2
3. evil-station (napadač)

## Pokretanje mreže na lokalnom računalu

**Kloniranje repozitorija**

```powershell
$ git clone https://github.com/mcagalj/SRP-2021-22
```

**Ulazak u novi direktorij**

```powershell
$ cd SRP-2021-22/arp-spoofing/
```

```powershell
$ cd SRP-2021-22/arp-spoofing/
```

- u direktoriju su se nalazile već gotove skripte start.sh i stop.sh za pokretanje i zaustavljanje virtualiziranog mrežnog scenarija što možemo provjeriti naredbom code .

## Naredbe i alati u Linuxu

**Pokretanje i zaustavljanje virtualiziranog mrežnog scenarija**

```powershell
$ ./start.sh 
```

```powershell
$ ./stop.sh
```

**Pokretanje shella**

```powershell
$ docker ps exec -it sh
```

**Provjera informacija (IP adrese i adrese mrežnog uređaja)**

```powershell
$ ifconfig -a
```

- uz pomoć dobivenih informacija pratimo jesmo li uspješno izvršili napad

**Provjera nalazi li se station-2 na istoj mreži**

```powershell
$ ping station-2
```

**Pokretanje shella u drugom kontejneru**

```powershell
$ docker exec -it station-2 sh
```

**Ostvarivanje komunikacije između station-1 i station-2** 

```powershell
$ netcat -lp 9000
```

- za ovakav način komunikacije treba znati IP adresu i port

```powershell
$ netcat station-1 9000
```

**Pokretanje shella u trećem kontejneru (napadača)**

```powershell
$ docker exec -it evil-station sh
```

## Napad na žrtvu

**Pokretanje napada**

```powershell
$ arpspoof -t station-1 station-2
```

```powershell
$ tcpdump
```

- sada pratimo razgovor između station-1 i station-2 bez njihova znanja

**Završetak napada**

```powershell
$ echo 0 > /proc/sys/net/ipv4/ip_forward
```

## 2. laboratorijske vježbe

26.10.2021.

## Zadatak

Dešifrirati odgovarajući *ciphertext* u kontekstu simetrične kriptografije. Izazov počiva na činjenici da student nema pristup enkripcijskom ključu.

Za pripremu *crypto* izazova, odnosno enkripciju korištena je Python biblioteka `[cryptography](https://cryptography.io/en/latest/)`. *Plaintext* koji student treba otkriti enkriptiran je korištenjem *high-level* sustava za simetričnu enkripciju iz navedene biblioteke - [Fernet](https://cryptography.io/en/latest/fernet/).

Fernet koristi sljedeće *low-level* kriptografske mehanizme:

- AES šifru sa 128 bitnim ključem
- CBC enkripcijski način rada
- HMAC sa 256 bitnim ključem za zaštitu integriteta poruka
- Timestamp za osiguravanje svježine (*freshness*) poruka

## Rad u Pythonu

**Stvaranje virtualnog okruženja**

```powershell
$ pipenv shell
```

**Instaliranje paketa cryptography i pokretanje pythona**

```powershell
$ pip install cryptography
```

```powershell
$ python
```

**Enkripcija i dekripcija**

```python
from cryptography.fernet import fernet

plaintext = b"Hello World"

key = Fernet.generate_key();
f = Fernet(key);

ciphertext = f.encrypt(plaintext);
f.decrypt(ciphertext);
```

-Prvo smo zadali neki tekst koji želimo enkriptirati. Zatim generiramo enkripcijski ključ koji nam je potreban za enkripciju plaintexta

-Nakon enkripcije koristimo ključ i za dekripciju ciphertexta

**Preuzimanje osobnog izazova na računalo**

```python
from cryptography.hazmat.primitives import hashes

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

filename = hash('jukic_borna') + ".encrypted"
```

**Program za enkripciju**

```python
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

def test_png(header):
    if header.startswith(b"\211PNG\r\n\032\n"):
        return True

def brute_force():
    filename = "3f7699d1bc4ee53a3e8f24bf77a150260f938f45b8d6a538819129263bd13.encrypted"
    with open(filename, "rb") as file:
        ciphertext = file.read()

    ctr = 0
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)

        if not (ctr + 1) % 1000:
            print(f"[*] Keys tested: {ctr + 1:,}", end="\r")

        try:    
            plaintext = Fernet(key).decrypt(ciphertext)
            
            header = plaintext[:32]
            if test_png(header):
                print(f"[+] KEY FOUND: {key}")
                with open("BINGO.png", "wb") as file:
                    file.write(plaintext)         
                break

        except Exception:
            pass
            
        ctr += 1

if __name__ == "__main__":
    brute_force()
```

-Pokrećemo brute_force napad koji će se vrtiti sve dok se ne pronađe ključ, a u terminalu će nam ispisivati koliko je ključeva do sada provjerio iz skupa ključeva

-S obzirom da bi oduzimalo puno vremena, postavljeno je da to ispiše nakon svakog provjerenog tisućitog ključa

-Kada pronađe ključ, program se terminira te stvara datoteku u koju postavlja dekriptirani ciphertext tj. plaintext koja je u našem slučaju slika

NAPOMENA: pod filename je svatko dobio svoju datoteku iz servera koju je trebalo dekriptirati

## 3. laboratorijske vježbe

9.11.2021.

Cilj vježbe je primjeniti teoreteske spoznaje o osnovnim kritografskim mehanizmima za autentikaciju i zaštitu integriteta poruka u praktičnom primjerima. Pri tome ćemo koristiti simetrične i asimetrične krito mehanizme: *message authentication code (MAC)* i *digitalne potpise* zasnovane na javnim ključevima.

**Izrada virtualnog okruženja**

```powershell
> mkdir jukic_borna
> cd jukic_borna
> python -m venv jukic_borna
> cd jukic_borna
> cd Scripts
> activate
> cd..
> pip install cryptography
> code.
```

## 1. zadatak

Zadatak je implementirati zaštitu integriteta sadržaja dane poruke primjenom odgovarajućeg *message authentication code (MAC)* algoritma. Pri tome treba koristiti HMAC mehanizam iz Python biblioteka cyrptography.

- u lokalnom direktoriju smo kreirali tekstualnu datoteku odgovarajućeg sadržaja čiji integritet želimo zaštititi

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
    key = b"my secret"

    with open("message.txt", "rb") as file:
        content = file.read()

    mac = generate_MAC(key, content)

    with open("message.sig", "wb") as file:
        file.write(mac)
    
    with open("message.sig", "rb") as file:
        signature = file.read()

    is_authentic = verify_MAC(key, signature, content)
    print(is_authentic)
```

Kod se sastoji od dvije funkcije: 

1. generate_MAC - funkcija za izračun MAC vrijednosti za danu poruku
2. verify_MAC - funkcija za provjeru validnosti MAC-a za danu poruku

- u main funkciji prvo otvaramo datotetku message.txt pomoću with open te njezin sadržaj spremamo u varijablu content

- zatim pomoću navedene funkcije generiramo MAC

- nakon generiranja MAC-a otvaramo datoteku message.sig u koju taj MAC zapisujemo

- iz iste te datoteke čitamo sadržaj i spremamo ga u signature koji koristitmo u funkicji verify_MAC za provjeru validnosti poruke

-u prvom pokušaju program je ispisao True, a nakon promjene sadržaja False

## 2. zadatak

U ovom zadatku želimo utvrditi vremenski ispravnu skevencu transakcija sa odgovarajućim dionicama. Digitalno potpisani (primjenom MAC-a) nalozi za pojedine transakcije nalaze se na lokalnom web poslužitelju [http://a507-server.local](http://a507-server.local/)

-sa servera preuzimamo personalizirane izazove

Preuzimanje izazova sa servera:

- Preuzeti program `wget` dostupan na [wget download](https://eternallybored.org/misc/wget/)
- Pohraniti ga u direktorij gdje pišemo kod za rješavanje ovog zadataka
- Osobne izazove preuzimamo izvršavanjem sljedeće naredbe

```powershell
> wget.exe -r -nH -np --reject "index.html*" http://a507-server.local/challenges/jukic_borna
```

-za provjeru MAC-a treba nam ključ koji je dobiven iz našeg imena sljedećom naredbom

```powershell
key = "jukic_borna".encode()
```

-za rješenje ovog zadatka koristimo se kodom iz prethodnog zadatka kojeg modificiramo

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import os 

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
    key = "jukic_borna".encode()

    path = os.path.join("challenges", "jukic_borna", "mac_challenge")
        
    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"
        msg_filepath = os.path.join(path, msg_filename)
        sig_filepath = os.path.join(path, sig_filename)

        with open(msg_filepath, "rb") as file:
            msg = file.read()   
        with open(sig_filename, "rb") as file:
            sig = file.read()  

        is_authentic = verify_MAC(key, sig, msg)

        print(f'Message {msg.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

-koristimo funkciju os.path.join kako bi kreirali odgovarajuću putanju do dokumenta

-kako ne bi pisali kod za provjeru svake transakcije, koristimo for petlju pomoću koje prolazimo kroz sve transakcije koje su označene brojevima te ih lijepimo na putanju do samih koja nam treba za otvoriti dokument i pročitati ga (ostatak koda je isti kao u prethodnom zadatku)s

## 4. laboratorijske vježbe

14.12.2021.

Napomena: na ovim vježbama, radimo i zaostali zadatak iz 3. laboratorijske vježbe 

U ovom vježbama trebamo odrediti autentičnu sliku (između dvije ponuđene) koju je profesor potpisao svojim privatnim ključem. Odgovarajući javni ključ nalazimo na serveru.

Slike i odgovarajući digitalni potpisi nalaze se u direktoriju `jukic_borna\public_key_challenge`. Kao i u prethodnoj vježbi, za rješavanje zadatka koristimo Python biblioteku `[cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)` tj. RSA kriptosustav.

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY
```

-pomoću navedenog koda učitajemo javni ključ iz datoteke

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True
```

-navedeni kod nam služi kako bi provjerili ispravnost digitalnog potpisa

-funkcija daje odgovor True ili False ovisno o tome podudara li se određena slika sa digitalno potpisanom slikom

## Zadatak

Zaporke/lozinke su najzastupljeniji način autentikacije korisnika. U okviru vježbe upoznati ćemo se pobliže sa osnovnim konceptima relevantnim za sigurnu pohranu lozinki. Usporediti ćemo klasične (*brze*) kriptografske *hash* funkcije sa specijaliziranim (*sporim* i *memorijski zahtjevnim*) kriptografskim funkcijama za sigurnu pohranu zaporki i izvođenje enkripcijskih ključeva (*key derivation function)*

-za potrebe vježbi kopirali smo cijeli kod dan u nastavku, no kako bi on funkcionirao trebamo lokalno kopirati datotetku requirements.txt koja sadrži popis modula koji su nam potrebni za pokretanje koda

-za instalaciju tih paketa koristimo naredbu

```powershell
pip install -r requirements.txt
```

**Kod potreban za zadatak**

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        }
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

-većina navedenih funkcija su kriptografske, no prva funkcija time_it nam prikazuje koliko vremena treba pozvanoj funkciji da se izvrši

-u main fukciji kreirali smo dva nova testa da vidimo koliko prosječno vremena njima treba u 100 pokretanja:

```python
 {"name": "Linux CRYPT 5k","service": lambda: linux_hash(password, measure=True)},

 {"name": "Linux CRYPT 1M","service": lambda: linux_hash(password, rounds=10 ** 6, measure=True},
```

Rezultat koji smo dobili:

```powershell
(jukic_borna) C:\Users\A507\jukic_borna\jukic_borna>python password_hashing.py
+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| AES      |       0.000495       |
+----------+----------------------+
 
 
+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| HASH_MD5 |       3.6e-05        |
| AES      |       0.000495       |
+----------+----------------------+
 
 
+-------------+----------------------+
| Function    | Avg. Time (100 runs) |
+-------------+----------------------+
| HASH_SHA256 |       3.1e-05        |
| HASH_MD5    |       3.6e-05        |
| AES         |       0.000495       |
+-------------+----------------------+
 
 
+----------------+----------------------+
| Function       | Avg. Time (100 runs) |
+----------------+----------------------+
| HASH_SHA256    |       3.1e-05        |
| HASH_MD5       |       3.6e-05        |
| AES            |       0.000495       |
| Linux CRYPT 5k |       0.005834       |
+----------------+----------------------+
 
 
+----------------+----------------------+
| Function       | Avg. Time (100 runs) |
+----------------+----------------------+
| HASH_SHA256    |       3.1e-05        |
| HASH_MD5       |       3.6e-05        |
| AES            |       0.000495       |
| Linux CRYPT 5k |       0.005834       |
| Linux CRYPT 1M |       1.211734       |
+----------------+----------------------+
```

-kao što vidimo na slici, svaka kriptografska hash funkcija ima različitu brzinu, no sporost neke funkcije ne znači da je ona lošija, kao što ni brzina ne znači da je ona bolja