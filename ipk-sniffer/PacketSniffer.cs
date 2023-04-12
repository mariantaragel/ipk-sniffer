using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ipk_sniffer;

public class PacketSniffer
{
    private static int _packetIndex;

    public static void SniffInterface(Options options)
    {
        var interfaces = LibPcapLiveDeviceList.Instance;

        using var adapter = interfaces.SingleOrDefault(i => i.Interface.FriendlyName == options.InterfaceName);
        if (adapter == null) {
            Console.Error.WriteLine($"Interface {options.InterfaceName} not found.");
            Environment.Exit(1);
        }

        /*
        const string capFile = "tcp.pcapng";
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice(capFile);
        offlineAdapter.Open(DeviceModes.Promiscuous);
        offlineAdapter.Filter = GetFilterString(options);
        while (offlineAdapter.GetNextPacket(out var pcap) == GetPacketStatus.PacketRead && _packetIndex < options.NumOfPacketsToDisplay) {
            OnPacketArrival(pcap);
        }
        */

        const int readTimeoutMilliseconds = 1000;
        adapter.Open(DeviceModes.Promiscuous, read_timeout: readTimeoutMilliseconds);

        while (adapter.GetNextPacket(out var pcap) == GetPacketStatus.PacketRead && _packetIndex < options.NumOfPacketsToDisplay) {
            OnPacketArrival(pcap);
        }

        adapter.Close();
    }

    private static void OnPacketArrival(PacketCapture pcap)
    {
        var dateTime = pcap.Header.Timeval.Date.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffK");
        var dataLen = pcap.Data.Length;
        var rawPacket = pcap.GetPacket();

        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ethernetPacket = packet.Extract<EthernetPacket>();
        var ipPacket = packet.Extract<IPPacket>();
        var tcpPacket = packet.Extract<TcpPacket>();

        if (tcpPacket != null)
        {
            var srcMac = MacAddressToString(ethernetPacket.SourceHardwareAddress);
            var dstMac = MacAddressToString(ethernetPacket.DestinationHardwareAddress);
            var srcIp = ipPacket.SourceAddress;
            var dstIp = ipPacket.DestinationAddress;
            int srcPort = tcpPacket.SourcePort;
            int dstPort = tcpPacket.DestinationPort;

            Console.WriteLine($"timestamp: {dateTime}\n" +
                              $"src MAC: {srcMac}\n" +
                              $"dst MAC: {dstMac}\n" +
                              $"frame length: {dataLen} bytes\n" +
                              $"src IP: {srcIp}\n" +
                              $"dst IP: {dstIp}\n" +
                              $"src port: {srcPort}\n" +
                              $"dst port: {dstPort}");
            Console.WriteLine();
            HexDump(rawPacket.Data);
        }
        _packetIndex++;
    }

    private static string GetFilterString(Options options)
    {
        var filterString = string.Empty;
        if (options.TcpOption) {
            filterString += "tcp";
        }
        if (options.UdpOption) {
            filterString += "udp";
        }

        return filterString;
    }

    private static string MacAddressToString(PhysicalAddress macAddress)
    {
        var macAddressString = macAddress.ToString().ToLower();
        macAddressString = Regex.Replace(macAddressString, ".{2}", ":$0").Remove(0, 1);
        return macAddressString;
    }

    private static void HexDump(byte[] bytes)
    {
        var offset = 0;
        for (var i = 1; i <= bytes.Length; i++)
        {
            var hex = BitConverter.ToString(bytes[(i - 1)..i]).ToLower();

            switch (i % 16)
            {
                case 0:
                    Console.Write(" " + hex + " ");
                    PrintChars(bytes[offset..i]);
                    Console.WriteLine();
                    offset += 16;
                    break;
                case 1:
                    PrintOffset(offset);
                    Console.Write(hex);
                    break;
                default:
                    Console.Write(" " + hex);
                    break;
            }
        }

        var left = bytes.Length - offset;
        var padRight = string.Empty.PadRight((3 * 16) - (3 * left - 1), ' ');
        Console.Write(padRight);
        PrintChars(bytes[offset..bytes.Length]);
    }

    private static void PrintChars(byte[] bytes)
    {
        for (var index = 0; index < bytes.Length; index++)
        {
            var b = bytes[index];
            var c = Convert.ToChar(b);
            
            if (c is >= ' ' and <= '~') {
                Console.Write(c);
            }
            else {
                Console.Write(".");
            }

            if (index == 7) {
                Console.Write(" ");
            }
        }
    }

    private static void PrintOffset(int offset)
    {
        Console.Write("0x" + offset.ToString("x4") + ": ");
    }
}