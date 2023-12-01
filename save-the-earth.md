```
La chargée RSE d'une organisation bien connue, Greenbiovitalia, communique beaucoup sur les réseaux sociaux.
Nous craignons que cette mauvaise habitude porte préjudice à la sécurité de cet organisme...
Tentez d'en savoir plus sur la chargée RSE de Greenbiovitalia !
```

Ce challenge est taggué #osint #exploit et propose un accès VPN.
En faisant une simple recherche sur Greenbiovitalia on découvre un compte twitter.

![image](https://github.com/nikaiw/dghack2023/assets/1255732/5972bdd2-7718-408b-ae5f-85f7a0bd7758)


![image](https://github.com/nikaiw/dghack2023/assets/1255732/df3f1217-0fe0-4561-aa05-e822d53236b8)

A première vue, le compte twitter ne semble pas donner beaucoup d'information si ce n'est l'adresse mail avec le nom de domaine de la société.

En se connectant sur le VPN on obtient une pour les deux /24 suivants:

* 172.10.15.0/24
* 10.10.2.0/24


Le premier est celui sur laquelle on récupère une IP et ou est présent notre gateway **172.10.15.253** qui est declaré aussi comme serveur DNS.
Lors d'une première tentative, probablement à cause d'une surcharge de l'infra, rien ne répond sur la range 10.10.2.0/24.

Le serveur DNS répond bien.

```
;; ANSWER SECTION:
dns.greenbiovitalia.ctf. 604800    IN    A    172.10.15.253
```

Disposant du domaine de la société, on se lance dans une énumération DNS.

```
python3 dnsrecon.py -n 172.10.15.253 -D namelist.txt -d greenbiovitalia.ctf
```

Le seul resultat interessant obtenu est le MX:
```MX smtp.greenbiovitalia.ctf 10.10.2.5```
