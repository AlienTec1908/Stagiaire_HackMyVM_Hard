# Stagiaire - HackMyVM (Hard)
 
![Stagiaire.png](Stagiaire.png)

## Übersicht

*   **VM:** Stagiaire
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Stagiaire)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 22. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Stagiaire_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der Challenge "Stagiaire" war die Erlangung von User- und Root-Rechten auf einer als "Hard" eingestuften Maschine. Der Lösungsweg umfasste mehrere Eskalationsstufen. Zunächst wurde durch Web-Enumeration und das Ausnutzen einer Fehlkonfiguration (POST-Anfragen auf geschützte Ressourcen) eine Bilddatei (`madonna.jpg`) heruntergeladen. Steganographie auf dieser Datei offenbarte die Passphrase `freeze` für eine versteckte Datei `info.txt`, deren Inhalt einen weiteren Pfad (`/madonnasecretlife`) preisgab. Dieser Pfad führte zu einer WordPress-Installation. Nachdem Brute-Force-Versuche auf WordPress und SSH fehlschlugen, wurde der SMTP-Dienst genutzt: Eine E-Mail an `madonna@stagiaire.hmv` mit einem Link zu einem Reverse-Shell-Payload führte zum initialen Zugriff als Benutzer `madonna`. Die Eskalation erfolgte dann zu `paillette` durch Auslesen von dessen SSH-Schlüssel (ermöglicht durch unsichere Gruppenberechtigungen und eine `tail`-Anomalie), dann zu `tony` durch Ausnutzung einer `sudo`-Regel für `/usr/bin/compose` zum Auslesen von dessen SSH-Schlüssel. Schließlich wurde Root-Zugriff durch eine Command Injection in einem PHP-Skript (`ping.php`) erlangt, das `tony` via `sudo` als Root starten konnte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `nikto`
*   `wfuzz`
*   `dig`
*   `curl`
*   `wget`
*   `steghide`
*   `stegseek`
*   `ssh`
*   `gobuster`
*   `wpscan`
*   `hydra`
*   `nc` (netcat)
*   `python3`
*   `stty`
*   `cat`
*   `vi` (impliziert)
*   `chmod` (impliziert)
*   `find`
*   `nano` (impliziert)
*   `sudo`
*   `mysql` (bzw. `mariadb-client`)
*   `ln`
*   `ls`
*   `tail`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Stagiaire" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.109`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1), 25 (SMTP - Postfix), 80 (HTTP - Apache 2.4.51 mit HTTP Basic Auth).
    *   `nikto` auf Port 80 bestätigte Basic Auth und meldete fehlende Security Header.
    *   VHost-Enumeration mit `wfuzz` war erfolglos.

2.  **Web Enumeration & Hint Finding:**
    *   Eine `PUT`-Anfrage an `/index.php` auf Port 80 gab einen HTML-Schnipsel mit `madonna.jpg` zurück.
    *   Download von `madonna.jpg` mittels `curl -X POST` (umging Basic Auth, die nur für GET galt).
    *   `stegseek` auf `madonna.jpg` fand mit Passphrase `freeze` die versteckte Datei `info.txt`.
    *   Inhalt von `info.txt`: "Don't waste your time I hate CTFs lol" (Sackgasse).
    *   `curl -X POST http://192.168.2.109/info.txt` (Pfad aus Dateinamen der Steganographie) lieferte den Pfad `/madonnasecretlife`.

3.  **WordPress Enumeration:**
    *   `gobuster` auf `/madonnasecretlife` identifizierte eine WordPress-Installation.
    *   `wpscan` gegen WordPress (Benutzer `madonna`) mit `rockyou.txt` war (vermutlich) erfolglos.
    *   SSH Brute-Force gegen `madonna` mit `hydra` wurde abgebrochen.

4.  **Initial Access (SMTP Vector):**
    *   Erstellung einer `index.html` auf dem Angreifer-System mit einem Bash-Reverse-Shell-Payload.
    *   Starten eines Python HTTP-Servers (Port 8000) zum Hosten der `index.html`.
    *   Starten eines `nc`-Listeners auf Port 9001.
    *   Manuelle SMTP-Sitzung via `nc` zum Ziel (Port 25): Senden einer E-Mail an `madonna@stagiaire.hmv` mit dem Link `http://[Angreifer-IP]:8000` als Inhalt.
    *   Erfolgreiche Reverse Shell als Benutzer `madonna` auf dem Listener. Stabilisierung der Shell.

5.  **Privilege Escalation (madonna -> paillette):**
    *   Auslesen der `wp-config.php` der WordPress-Installation als `madonna` -> Fund des DB-Passworts `@Acensi2021*` für den DB-Benutzer `madonna`.
    *   Das Passwort `@Acensi2021*` war auch das Login-Passwort für `madonna` (bestätigt durch `sudo -l` Versuch). `madonna` hatte keine Sudo-Rechte.
    *   Die MariaDB-Datenbank (wordpress_db) enthielt nur den Benutzer `madonna`, keine weiteren Hinweise.
    *   Im Verzeichnis `/home/paillette/tetramin` (Zugriff für Gruppe `www-data`, zu der `madonna` vermutlich gehört oder andere unsichere Berechtigung) wurde durch Erstellen eines Symlinks und Auslesen mit `tail` (umging direkte Lesebeschränkungen) der private SSH-Schlüssel von `paillette` (`/home/paillette/tetramin/ssh/id_rsa`) extrahiert.
    *   Login als `paillette` via SSH mit dem extrahierten Schlüssel.

6.  **Privilege Escalation (paillette -> tony):**
    *   `sudo -l` als `paillette` zeigte: `(tony) NPASSWD: /usr/bin/compose`.
    *   Ausnutzung von `/usr/bin/compose` (wahrscheinlich durch Manipulation der `PAGER`-Umgebungsvariable oder eine direkte Funktion von `compose`) im Kontext von `tony`, um dessen privaten SSH-Schlüssel (`/home/tony/.ssh/id_rsa`) auszulesen.
    *   Login als `tony` via SSH mit dem extrahierten Schlüssel.

7.  **Privilege Escalation (tony -> root):**
    *   User-Flag (`2d82acbaf36bbd1b89b9e3794ba90a91`) in `/home/tony/user.txt` gelesen.
    *   `.bash_history` von `tony` war deaktiviert (Link zu `/dev/null`).
    *   `sudo -l` als `tony` zeigte: `(ALL : ALL) NOPASSWD: /bin/bash /srv/php_server`.
    *   Ausführen von `sudo -u root /bin/bash /srv/php_server` startete einen PHP-Entwicklungsserver auf `127.0.0.1:8000`.
    *   Der Server führte ein Skript `/ping.php` aus, das eine Command Injection Schwachstelle im GET-Parameter `ip` hatte.
    *   Aufbau eines SSH Port Forwardings (`ssh -L 8001:127.0.0.1:8000 ...`) um auf den lokalen PHP-Server zuzugreifen.
    *   Ausnutzung der Command Injection via `curl "http://127.0.0.1:8001/ping.php?ip=;[BEFEHL]"` zur Ausführung von Befehlen als `root` und zum Lesen der Root-Flag.

## Wichtige Schwachstellen und Konzepte

*   **Fehlkonfiguration HTTP Basic Auth:** Schutz nicht auf alle HTTP-Methoden (POST) angewendet.
*   **Steganographie (madonna.jpg):** Verstecken von Hinweisen (Pfad) in einer Bilddatei.
*   **SMTP als Angriffsvektor:** Senden einer präparierten E-Mail, die einen Link zu einem Reverse-Shell-Payload enthält.
*   **Unsichere Dateiberechtigungen & Symlink-Missbrauch:** Auslesen eines privaten SSH-Schlüssels durch unsichere Gruppenberechtigungen und die Fähigkeit, Symlinks zu erstellen, wobei `tail` Lesebeschränkungen umging.
*   **Passwortwiederverwendung / Klartext-Credentials:** Datenbankpasswort war identisch mit dem Benutzerpasswort und in `wp-config.php` gespeichert.
*   **Unsichere `sudo`-Regeln:**
    *   Ausführung von `/usr/bin/compose` erlaubte das Auslesen von Dateien im Kontext eines anderen Benutzers.
    *   Ausführung eines Skripts (`/srv/php_server`) als Root, welches eine Command Injection enthielt.
*   **Command Injection in PHP-Skript:** Ein unsicher programmierter `ping`-Mechanismus im PHP-Server erlaubte die Ausführung beliebiger Befehle als Root.
*   **SSH Port Forwarding:** Umgehung von Netzwerkbeschränkungen (Server lauscht nur lokal) durch Weiterleiten eines lokalen Ports.

## Flags

*   **User Flag (`/home/tony/user.txt`):** `2d82acbaf36bbd1b89b9e3794ba90a91`
*   **Root Flag (via Command Injection gelesen):** `9ed378ce95f7ea505366c55aeaf12bea`

## Tags

`HackMyVM`, `Stagiaire`, `Hard`, `SMTP`, `Steganography`, `WordPress`, `SSH Key Extraction`, `Sudo Exploitation`, `Command Injection`, `PHP`, `compose`, `Linux`, `Web`, `Privilege Escalation`
