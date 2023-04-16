﻿using System.Net;
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
        using var adapter = GetInterface(options.InterfaceName);

#if DEBUG
        const string capFile = "filter.pcapng";
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice(capFile);
        offlineAdapter.Open(DeviceModes.Promiscuous);
        var filter = new Filter();
        filter.OptionsToString(options);
        offlineAdapter.Filter = filter.FilterString;
        while (offlineAdapter.GetNextPacket(out var pcap) == GetPacketStatus.PacketRead && _packetIndex < options.NumOfPacketsToDisplay) 
        {
            OnPacketArrival(pcap, options);
        }
#else
        adapter.Open(DeviceModes.Promiscuous);
        var filter = new Filter();
        filter.OptionsToString(options);
        adapter.Filter = filter.FilterString;
        while (adapter.GetNextPacket(out var pcap) == GetPacketStatus.PacketRead && _packetIndex < options.NumOfPacketsToDisplay) {
            OnPacketArrival(pcap, options);
        }
        Console.WriteLine(adapter.Statistics.ToString());
        adapter.Close();
#endif
    }

    private static LibPcapLiveDevice GetInterface(string? interfaceName)
    {
        var interfaces = LibPcapLiveDeviceList.Instance;
        var adapter = interfaces.SingleOrDefault(i => i.Interface.FriendlyName == interfaceName);
        
        if (adapter == null) {
            Console.Error.WriteLine($"Interface {interfaceName} not found.");
            Environment.Exit(1);
        }

        return adapter;
    }

    public static void OnPacketArrival(PacketCapture pcap, Options options)
    {
        var (dateTime, dataLen) = GetDateTimeAndLen(pcap);

        var rawPacket = pcap.GetPacket();
        if (rawPacket.LinkLayerType != LinkLayers.Ethernet) {
            return;
        }
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ethernetHeader = (EthernetPacket)packet;
        var (srcMac, dstMac) = GetMacAddress(ethernetHeader);

        IPAddress? srcIp = null;
        IPAddress? dstIp = null;
        var internetPacket = packet.PayloadPacket;
        IPPacket? internetHeader = null;
        if (packet.HasPayloadPacket) {
            if (ethernetHeader.Type is EthernetType.IPv4 or EthernetType.IPv6) {
                internetHeader = (IPPacket)internetPacket;
                srcIp = internetHeader.SourceAddress;
                dstIp = internetHeader.DestinationAddress;
            }
        }

        ushort? srcPort = null;
        ushort? dstPort = null;
        if (internetPacket.HasPayloadPacket && internetHeader?.Protocol != null) {
            var transportPacket = internetPacket.PayloadPacket;
            switch (internetHeader.Protocol)
            {
                case ProtocolType.Udp: case ProtocolType.Tcp:
                    var transportHeader = (TransportPacket)transportPacket;
                    srcPort = transportHeader.SourcePort;
                    dstPort = transportHeader.DestinationPort;
                    break;
                case ProtocolType.IcmpV6 when options.MldOption:
                    var mldPacket = (IcmpV6Packet)transportPacket;
                    if ((int)mldPacket.Type is not (>= 130 and <= 132 or 143)) {
                        return;
                    }
                    break;
            }
        }

        Console.WriteLine(ethernetHeader);
        PrintPacket(dateTime, srcMac, dstMac, dataLen, srcIp, dstIp, srcPort, dstPort, rawPacket);
        Console.WriteLine();
        _packetIndex++;
    }

    public static (string srcMac, string dstMac) GetMacAddress(EthernetPacket ethernetHeader)
    {
        var srcMac = MacAddressToString(ethernetHeader.SourceHardwareAddress);
        var dstMac = MacAddressToString(ethernetHeader.DestinationHardwareAddress);
        return (srcMac, dstMac);
    }

    public static (string dateTime, int dataLen) GetDateTimeAndLen(PacketCapture pcap)
    {
        var dateTime = pcap.Header.Timeval.Date.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK");
        var dataLen = pcap.Data.Length;
        return (dateTime, dataLen);
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
        Console.WriteLine();
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