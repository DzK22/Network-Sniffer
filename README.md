# Analyseur Réseau (Sniffeur)

Projet Service Réseaux M1 SIRIS - Université de Strasbourg

Protocoles Supporté :
- Ethernet
- IPv4, IPv6, ARP
- UDP, TCP, ARP
- BOOTP/DHCP, DNS, HTTP/HTTPS, FTP, SMPT, POP, IMAP, TELNET, OSPFv2

#Architecture
- /src : Fichiers sources
- /headers : fichiers include

##Auteur

Danyl EL-KABIR

##Utilisation

1. make
2. sudo ./nSniffeur avec les options suivantes :
```
-i <interface> : interface pour l'analyse live
-o <fichier> : fichier d’entrée pour l’analyse offline
-f <filtre> : filtre BPF (optionnel)
-v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)
```
