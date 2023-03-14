# Lab Title: [Insert title here]

## Challenge Answers

- **Challenge 1:** [Insert answer here, i.e., a Chuck Norris fact]
- **Challenge 2:** [Insert answer here, i.e., a `password` to unlock the next lab]

## Other Relevant Information

[Insert here, if applicable]
  
## Lab Prep Questions and Answers

[Insert below, if applicable]

1. What is the _Address Resolution Protocol (ARP)_, and what is its role in a network?
    - ARP protokol je komunikacijski protokol koji poovezuje IP adresu s MAC (Media access control) adresom računala pa na taj 
      način iz poznate mrežne adrese (IP) u nekom LAN-u možemo dobiti fizičku adresu (MAC) nekog računala u toj mreži
  
2. What is a _Man-in-the-Middle (MitM)_ attack, and how does ARP spoofing enable it?
   - Man in the middle je oblik cyber napada u kojem se napadač dovede u poziciju da sva komunikacija između neka dva računala prolazi
     preko njega bez da oni to znaju. Na taj način osim što je narušena povjerljivost jer napdač čita sve poruke, može bit narušen i 
     integritet kako ih on može mijenjati. ARP spoofing to omogućuje jer se ARP zahtjev šalje svim računalima u mreži pa se napadač može
     lažno predstaviti kao traženo računalo.

3. How does an attacker use ARP spoofing to intercept network traffic?
   - Tako da se lažno predstavi kao računalo s kojim je ARP zahtjevom zapravo zatražena komunikacija
  
4. How is the _cookie_ used to derive the encryption/decryption key?
   - Cookie je tajna vrijednost koja se proslijedi funkciji koja koristeći njega izvede enkripcijski/dekrpcijski ključ

5. What REST API request do you need to send to the _crypto oracle_ the secret cookie?
   - Tajni cookie se može dobiti slanjem sljedećeg REST API zahtjeva crypto oracle serveru: GET /arp/cookie
  
6. How do you obtain the authentication token?
   - Tako da presluškujemo komunikaciju između servera i arp_clienta
  
7. How do you use the authentication token to obtain the cookie?
   - Pošaljemo _crypto oracle_ zahtjev s odgovarajućim autentikacijskim tokenom

8. What encryption mode is used to encrypt the challenge in this lab?
   - AES šifra u CBC enkripcijskom modu 

9. What tool can you use to capture network traffic on a local network interface?
   - tcpdump
