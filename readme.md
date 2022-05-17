Vidéo de présentation : https://youtu.be/eMsH8h4Ksfo

ReadMe – Analyseur de protocoles réseau ‘Offline’

Ce projet réalisé par ma coéquipière TRAORE KHADIDJA et moi-même IKHLEF NADJIA a été fait dans le but d'analyser des trames préalablement capturées sur un réseau Ethernet. 
En d’autres termes, notre application représente un analyseur de protocoles réseau offline.

Ce projet a été réalisé dans le contexte d'un travail demandé par notre université, il se sépare en deux parties : 
- le côté programmation où l'on a utilisé Python.
- le côté graphique où l'on a utilisé Tkinter la bibliothèque graphique de Python

Notre analyseur comprend les protocoles de la couche 2 (Ethernet), la couche 3 (IP), la couche 4 (TCP) et la couche 7 (HTTP). 
Il reconnaît également les options IP suivante : End Of Option List, No opération, Record route, Time Stamp, Loose Source Route, 
Strict Source Route et sait lire toute les options de TCP (du type 0x00 à 0x0F).

Notre analyseur pourra éventuellement être développé dans le futur afin de comprendre d'autres protocoles tel que ARP, UDP, ICMP etc... Et ainsi être complet et plus performant.

Afin d'assurer le bon fonctionnement de l'analyseur, les fichiers textes possédant les trames et que vous entrez doivent respecter certains conditions :

- l'offset doit être sur 2 octets et séparer des autres octets par un espace.
- chaque octet est codé sur 2 symboles et doit être séparé d'un espace des autres octets.
- chaque ligne doit posséder des caractères spéciaux à ignorer de longueur supérieure à 4 (c'est d’ailleurs généralement tout le temps le cas).

L'analyseur se charge en plus d'analyser les différentes trames :
- d'ignorer toutes lignes ne commençant pas avec un offset valide.
- de détecter les lignes incomplètes.
- d'ignorer tout texte entre les lignes de la trame ou bien à la fin de lignes.



L’ensemble du code se trouve dans le fichier analyseur.py. Dedans, on y trouve :
	- une partie qui permet demander à l’utilisateur d’entrer un fichier texte et de lire ce fichier texte. Et de créer le fichier « resultat.txt ». 
	- une partie qui crée la fenêtre graphique
	- la fonction trames()
	- la fonction retirerchamp(liste, tailleChamp)
	- la fonction retirerChampHTTP(l, jusquaOctet)
	- la fonction analyseur()
	- un appel aux fonctions trames() et analyseur()
