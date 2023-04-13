using System.Net;
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

        const string capFile = "icmpv4.pcap";
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice(capFile);
        offlineAdapter.Open(DeviceModes.Promiscuous);
        offlineAdapter.Filter = "icmp";
        while (offlineAdapter.GetNextPacket(out var pcap) == GetPacketStatus.PacketRead && _packetIndex < options.NumOfPacketsToDisplay) {
            OnPacketArrival(pcap);
        }

        /*
        const int readTimeoutMilliseconds = 1000;
        adapter.Open(DeviceModes.Promiscuous, read_timeout: readTimeoutMilliseconds);

        while (adapter.GetNextPacket(out var pcap) == GetPacketStatus.PacketRead && _packetIndex < options.NumOfPacketsToDisplay) {
            OnPacketArrival(pcap);
        }

        adapter.Close();
        */
    }

    private static void OnPacketArrival(PacketCapture pcap)
    {
        var dateTime = pcap.Header.Timeval.Date.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffK");
        var dataLen = pcap.Data.Length;
        var rawPacket = pcap.GetPacket();

        if (rawPacket.LinkLayerType != LinkLayers.Ethernet) {
            return;
        }
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ethernetHeader = (EthernetPacket)packet;
        var srcMac = MacAddressToString(ethernetHeader.SourceHardwareAddress);
        var dstMac = MacAddressToString(ethernetHeader.DestinationHardwareAddress);

        IPAddress? srcIp = null;
        IPAddress? dstIp = null;
        var internetPacket = packet.PayloadPacket;
        if (packet.HasPayloadPacket) {
            if (ethernetHeader.Type is EthernetType.IPv4 or EthernetType.IPv6) {
                var internetHeader = (IPPacket)internetPacket;
                srcIp = internetHeader.SourceAddress;
                dstIp = internetHeader.DestinationAddress;
            }
        }

        ushort? srcPort = null;
        ushort? dstPort = null;
        if (internetPacket.HasPayloadPacket) {
            var transportPacket = internetPacket.PayloadPacket;
            var transportHeader = (TransportPacket)transportPacket;
            srcPort = transportHeader.SourcePort;
            dstPort = transportHeader.DestinationPort;
        }

        PrintPacket(dateTime, srcMac, dstMac, dataLen, srcIp, dstIp, srcPort, dstPort, rawPacket);
        _packetIndex++;
    }

    private static void PrintPacket(string dateTime, string srcMac, string dstMac, int dataLen, IPAddress? srcIp, IPAddress? dstIp, ushort? srcPort, ushort? dstPort,
        RawCapture rawPacket)
    {
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