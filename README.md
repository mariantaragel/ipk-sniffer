# IPK Projekt 2
Cie�om projektu je implementova� paketov� sniffer, ktor� bude schopn� zachyti�, filtova� a zobrazi� pakety na na �pecifickom sie�ovom rozhran�.

## �trukt�ra projektu
Projek bol vypracovan� v jazyku C# a bol �trukturovan� do viacerich tried. Z�kldnou triedou je `Program`, ktor� obasuje funkciu `Main`, ktor� je vstupn�m bodom programu. Triedy `CommandLineOptions`, `OptionBinder` a `Options` s pomocou kni�nice `System.CommandLine` sprcuv�vaj� agrmunty pr�kazov�ho riadku. Trieda `NetworkInterfaces` zobrazuje aktu�lne sie�ov� rozhrania. Trieda `PacketSniffer` a kni�nica `SharpPcap` zachyt�vaj� pakety, n�sledne ich filtruj� a analyzuj�. Trieda `Filter` je pomocn� trieda, kror� trasformuje vstupn� argumenty na re�azec, ktor� filtruje prich�dzaj�ce pakety.

## UML Diagram
```mermaid
classDiagram
class Options
	Options : + InterfaceName
	Options : + NumOfPacketsToDisplay
	Options : + TcpOption
	Options : + UdpOption
	Options : + PortOption
	Options : + Icmp4Option
	Options : + Icmp6Option
	Options : + ArpOption
	Options : + NdpOption
	Options : + IgmpOption
	Options : + MldOption
class OptionBinder
class Program
    Program : + Main()
class NetworkInterfaces
	NetworkInterfaces : + DisplayInterfaces()
class Filter
	Filter : + OptionsToString()
```

## Te�ria
V nasleduj�cej �asti stru�ne zhrniem te�riu nutn� k pochopeniu implementovanej funkcionality. Zameriam sa hlavne na to �o je to paketov� sniffer a ako sa d� pou�i�. Vych�dza� budem zo zdroja [1].

### Paketov� sniffer
Paketov� sniffer je vo�ne dostupn� n�stroj, ktor� dok�e zachyti� a analyzova� pakety s konkr�tneho sie�ov�ho rozhrania. Jedn�m z najzn�mej��ch je Wireshark.

### Bezpe�nos�
Zachyt�vanie paketov predsatavuje potenci�lne bezpe�nostn� rizik�, preto�e pakety posielan� po sieti m��u obsahova�, citliv� inform�cie, ako napr�klad hesl�, osobn� inform�cie, s�kromn� spr�vy a in�. Ke�e je paketov� sniffer pas�vny n�stroj, nevklad� pakety do sie�ov�ho kan�lu, je �a�ko detekovate�n�. To znamen�, �e ak posielame d�ta po sieti, mus�me akceptova� mo�nos�, �e si �to�n�k m��e urobi� k�piu na�eho paketu. Najlep�ou obranou proti paketov�m snifferom je kryptografia a �ifrovanie paketov.

## Testovanie

## Bibliografia
[1] KUROSE James F. a Keith W. ROSS. <em>Computer networking: a top-down approach</em>. Eighth edition.; Global edition. Harlow: Pearson Education Limited, 2022, ISBN 978-1-292-40546-9.<br/>