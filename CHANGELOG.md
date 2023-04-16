# CHANGELOG
Projekt implementuje nasledujúcu funkcionalitu:
- Zobrazenia aktívnych sieovıch rozhraní aj s dodatoènımi informáciami (názov, popis, operaènı status a typ sieového rozhrania)
- Zachytenie paketov z konkrétneho sieového rozhrania
- Filtrovanie zachytenıch paketov pomocou argumentov príkazového riadku
- Vıpis podrobností o danom pakete (èasová znaèka, ve¾kos, zdrojová MAC adresa, cie¾ová MAC adresa, zdrojová IP adresa, cie¾ová IP adresa, zdrojovı port, cie¾ovı port)
- Hexadecimálny vıpis paketu
- Prepínaè --help vypíše pomocníka

V projekte nie je implementované:
- Podpora pre halvièky linkovej vrstvy, ktoré majú inı typ ako Ethernet
- Podpora pre iné protokoly ako TCP, UDP, ICMPv4, ICMPv6, ARP a IGMP