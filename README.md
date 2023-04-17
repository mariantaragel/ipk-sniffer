# IPK Projekt 2
Cieľom projektu je implementovať paketový sniffer, ktorý bude schopný zachytiť, filtrovať a zobraziť pakety na špecifickom sieťovom rozhraní.

## Štruktúra projektu
Projekt bol vypracovaný v jazyku C# a bol štruktúrovaný do viacerých tried. Základnou triedou je `Program`, ktorá obsahuje funkciu `Main`, ktorá je vstupným bodom programu. Triedy `CommandLineOptions`, `OptionBinder` a `Options` s pomocou knižnice `System.CommandLine` spracovávajú argumenty príkazového riadku. Trieda `NetworkInterfaces` zobrazuje aktuálne sieťové rozhrania. Trieda `PacketSniffer` a knižnica `SharpPcap` zachytávajú pakety, následne ich filtrujú a analyzujú.

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
	OptionBinder : + OptionBinder()
class CommandLineOptions
	CommandLineOptions : + CommandLineOptions()
	CommandLineOptions : + CreateRootCommand()
class Program
    Program : + Main()
class NetworkInterfaces
	NetworkInterfaces : + DisplayInterfaces()
class PacketSniffer
	PacketSniffer : + SniffInterface()
	PacketSniffer : + OnPacketArrival()
	PacketSniffer : + GetMacAddress()
	PacketSniffer : + GetDateTimeAndLen()
Program -- PacketSniffer
Program -- NetworkInterfaces
Program -- CommandLineOptions
Program -- OptionBinder
OptionBinder -- CommandLineOptions
OptionBinder -- Options
PacketSniffer -- Options
```

## Teória
V nasledujúcej časti stručne zhrniem teóriu nutnú k pochopeniu implementovanej funkcionality. Zameriam sa hlavne na to čo je to paketový sniffer a ako sa dá použiť. Vychádzať budem zo zdroja [1].

### Paketový sniffer
Paketový sniffer je voľne dostupný nástroj, ktorý dokáže zachytiť a analyzovať pakety s konkrétneho sieťového rozhrania. Jedným z najznámejších je Wireshark.

### Bezpečnosť
Zachytávanie paketov predstavuje potenciálne bezpečnostné riziká, pretože pakety posielané po sieti môžu obsahovať, citlivé informácie, ako napríklad heslá, osobné informácie, súkromné správy a iné. Keďže je paketový sniffer pasívny nástroj, nevkladá pakety do sieťového kanálu, je ťažko detekovateľný. To znamená, že ak posielame dáta po sieti, musíme akceptovať možnosť, že si útočník môže urobiť kópiu nášho paketu. Najlepšou obranou proti paketovým snifferom je kryptografia a šifrovanie paketov.

## Testovanie
Testovanie bolo uskutočnené pomocou automatizovaných testov v prostredí Xunit. Implementované testy sa nachádzajú v zložke tests v ktorej bol zavolaný príkaz `dotnet test`. Aplikácia bola testovaná v offline režime, to znamená, že sieťovú komunikáciu čítala z .pcap súborov, ktoré sa nachádzajú v zložke pcap. Overovalo sa správne prečítanie dátumu, času, veľkosti paketu, portov, MAC adries a IP adries.

Výstup z testovania:
```
[root@ipk-vm:/home/ipk/IPK-Projekt-2/tests]# dotnet test
  Determining projects to restore...
  All projects are up-to-date for restore.
  ipk-sniffer -> /home/ipk/IPK-Projekt-2/src/bin/Debug/net6.0/linux-x64/ipk-sniffer.dll
  ipk-sniffer-tests -> /home/ipk/IPK-Projekt-2/tests/bin/Debug/net6.0/ipk-sniffer-tests.dll
Test run for /home/ipk/IPK-Projekt-2/tests/bin/Debug/net6.0/ipk-sniffer-tests.dll (.NETCoreApp,Version=v6.0)
Microsoft (R) Test Execution Command Line Tool Version 17.3.1 (x64)
Copyright (c) Microsoft Corporation.  All rights reserved.

Starting test execution, please wait...
A total of 1 test files matched the specified pattern.

Passed!  - Failed:     0, Passed:     5, Skipped:     0, Total:     5, Duration: 32 ms - /home/ipk/IPK-Projekt-2/tests/bin/Debug/net6.0/ipk-sniffer-tests.dll (net6.0)
```

V druhej fáze testovania som sa zameral na správne filtrovanie paketov. K tomuto účelu bol vytvorený skript `test.py`, ktorý posiela na loopback adresu jednotlivé typy paketov. V tabuľke nižšie je prehľadne ukázané s akými vstupnými argumentami bol program `ipk-sniffer` spustený, aké pakety odoslal skript a ktoré z nich majú byť odfiltrované a ktoré sa majú prijať.

```
+----------------+-------------------------+------------------------------------+------------------+-----------------+
| test case      | argumenty               | vstup                              | očakávaný výstup | skutočný výstup |
+----------------+-------------------------+------------------------------------+------------------+-----------------+
| test_tcp       | -i lo -p 53 --tcp -n 2  | IP(dst='127.0.0.1')/TCP(dport=53)  | prijatý          | prijatý         |
|                |                         | IP(dst='127.0.0.1')/IGMP()         | vyfiltrovaný     | vyfiltrovaný    |
|                |                         | IP(dst='127.0.0.1')/TCP(dport=53)  | prijatý          | prijatý         |
+----------------+-------------------------+------------------------------------+------------------+-----------------+
| test_udp       | -i lo --udp             | IP(dst='127.0.0.1')/TCP(dport=53)  | vyfiltrovaný     | vyfiltrovaný    |
|                |                         | IP(dst='127.0.0.1')/UDP(dport=123) | prijatý          | prijatý         |
+----------------+-------------------------+------------------------------------+------------------+-----------------+
| test_multicast | -i lo --igmp --mld -n 2 | IP(dst='127.0.0.1')/IGMP()         | prijatý          | prijatý         |
|                |                         | IP(dst='127.0.0.1')/ICMP()         | vyfiltrovaný     | vyfiltrovaný    |
|                |                         | IPv6(dst='::1')/ICMPv6MLQuery()    | prijatý          | prijatý         |
+----------------+-------------------------+------------------------------------+------------------+-----------------+
| test_icmp      | -i lo --icmp4 --icmp6   | IP(dst='127.0.0.1')/IGMP()         | vyfiltrovaný     | vyfiltrovaný    |
|                |                         | IP(dst='127.0.0.1')/ICMP()         | prijatý          | prijatý         |
+----------------+-------------------------+------------------------------------+------------------+-----------------+
| test_arp       | -i lo --arp --ndp       | IP(dst='127.0.0.1')/TCP(dport=53)  | vyfiltrovaný     | vyfiltrovaný    |
|                |                         | ARP(pdst='127.0.0.1')              | prijatý          | prijatý         |
+----------------+-------------------------+------------------------------------+------------------+-----------------+
| test_num_opt   | -i lo -n 2              | IP(dst='127.0.0.1')/UDP(dport=123) | prijatý          | prijatý         |
|                |                         | P(dst='127.0.0.1')/IGMP()          | prijatý          | prijatý         |
+----------------+-------------------------+------------------------------------+------------------+-----------------+
| test_port      | -i lo -p 22 -n 2        | IP(dst='127.0.0.1')/UDP(dport=22)  | prijatý          | prijatý         |
|                |                         | IPv6(dst='::1')/ICMPv6MLQuery()    | vyfiltrovaný     | vyfiltrovaný    |
|                |                         | IP(dst='127.0.0.1')/TCP(dport=22)  | prijatý          | prijatý         |
+----------------+-------------------------+------------------------------------+------------------+-----------------+
| test_empty_cli | -i lo                   | ARP(pdst='127.0.0.1')              | prijatý          | prijatý         |
+----------------+-------------------------+------------------------------------+------------------+-----------------+
```

Aplikácia bola testovaná v poskytnutom virtuálnom stroji s operačným systémom Linux (distribúcia NixOS 22.11 Raccoon). Testy boli spúšťané na zariadení Dell Latitude 5491 (Intel Core i7, 8GB RAM DDR4, 256GB SSD). Testovaná aplikácia bola vo verzii 1.0.0.

## Bibliografia
[1] KUROSE James F. a Keith W. ROSS. <em>Computer networking: a top-down approach</em>. Eighth edition.; Global edition. Harlow: Pearson Education Limited, 2022, ISBN 978-1-292-40546-9.<br/>
