# CHANGELOG
Projekt implementuje nasleduj�cu funkcionalitu:
- Zobrazenia akt�vnych sie�ov�ch rozhran� aj s dodato�n�mi inform�ciami (n�zov, popis, opera�n� status a typ sie�ov�ho rozhrania)
- Zachytenie paketov z konkr�tneho sie�ov�ho rozhrania
- Filtrovanie zachyten�ch paketov pomocou argumentov pr�kazov�ho riadku
- V�pis podrobnost� o danom pakete (�asov� zna�ka, ve�kos�, zdrojov� MAC adresa, cie�ov� MAC adresa, zdrojov� IP adresa, cie�ov� IP adresa, zdrojov� port, cie�ov� port)
- Hexadecim�lny v�pis paketu
- Prep�na� --help vyp�e pomocn�ka

V projekte nie je implementovan�:
- Podpora pre halvi�ky linkovej vrstvy, ktor� maj� in� typ ako Ethernet
- Podpora pre in� protokoly ako TCP, UDP, ICMPv4, ICMPv6, ARP a IGMP