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
    private static Options _options = new();
    private static LibPcapLiveDevice? _adapter;

    public static void SniffInterface(Options options)
    {
        _options = CorrectOptions(options);
        _adapter = GetInterface(_options.InterfaceName);
        _adapter.OnPacketArrival += OnPacketArrival;
        try {
            _adapter.Open(DeviceModes.Promiscuous);
        }
        catch (PcapException e) {
            Console.WriteLine(e);
            Environment.Exit(1);
        }
        _adapter.Capture();
        Console.WriteLine(_adapter.Statistics.ToString());
        _adapter.Close();
    }

    private static LibPcapLiveDevice GetInterface(string? interfaceName)
    {
        var interfaces = LibPcapLiveDeviceList.Instance;
        var adapter = interfaces.SingleOrDefault(i => i.Interface.FriendlyName == interfaceName);

        if (adapter == null)
        {
            Console.Error.WriteLine($"Interface {interfaceName} not found.");
            Environment.Exit(1);
        }

        return adapter;
    }

    public static void OnPacketArrival(object sender, PacketCapture pcap)
    {
        var (dateTime, dataLen) = GetDateTimeAndLen(pcap);

        var rawPacket = pcap.GetPacket();
        if (rawPacket.LinkLayerType != LinkLayers.Ethernet)
        {
            return;
        }
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ethernetHeader = (EthernetPacket)packet;
        var (srcMac, dstMac) = GetMacAddress(ethernetHeader);

        IPAddress? srcIp = null;
        IPAddress? dstIp = null;
        var internetPacket = packet.PayloadPacket;
        IPPacket? internetHeader = null;
        if (packet.HasPayloadPacket)
        {
            switch (ethernetHeader.Type)
            {
                case EthernetType.IPv4 or EthernetType.IPv6:
                    internetHeader = (IPPacket)internetPacket;
                    srcIp = internetHeader.SourceAddress;
                    dstIp = internetHeader.DestinationAddress;
                    break;
                case EthernetType.Arp when _options.ArpOption:
                    break;
                default:
                    return;
            }
        }

        ushort? srcPort = null;
        ushort? dstPort = null;
        if (internetPacket.HasPayloadPacket && internetHeader?.Protocol != null)
        {
            var transportPacket = internetPacket.PayloadPacket;
            switch (internetHeader.Protocol)
            {
                case ProtocolType.Udp when _options.UdpOption:
                case ProtocolType.Tcp when _options.TcpOption:
                    var transportHeader = (TransportPacket)transportPacket;
                    srcPort = transportHeader.SourcePort;
                    dstPort = transportHeader.DestinationPort;
                    if (_options.PortOption != null)
                    {
                        if (srcPort != _options.PortOption && dstPort != _options.PortOption)
                        {
                            return;
                        }
                    }
                    break;
                case ProtocolType.IcmpV6:
                    if (_options is { Icmp6Option: false, MldOption: true, NdpOption: false })
                    {
                        var mldPacket = (IcmpV6Packet)transportPacket;
                        if ((int)mldPacket.Type is not (>= 130 and <= 132 or 143))
                        {
                            return;
                        }
                    }
                    else if (_options is { Icmp6Option: false, MldOption: false, NdpOption: true })
                    {
                        var ndpPacket = (IcmpV6Packet)transportPacket;
                        if ((int)ndpPacket.Type is not (>= 133 and <= 137))
                        {
                            return;
                        }
                    }
                    else if (_options is { Icmp6Option: false, MldOption: true, NdpOption: true })
                    {
                        var icmpV6Packet = (IcmpV6Packet)transportPacket;
                        if ((int)icmpV6Packet.Type is not ((>= 130 and <= 137) or 143))
                        {
                            return;
                        }
                    }
                    else if (_options.Icmp6Option) { }
                    else
                    {
                        return;
                    }
                    break;
                case ProtocolType.Igmp when _options.IgmpOption:
                    break;
                case ProtocolType.Icmp when _options.Icmp4Option:
                    break;
                default:
                    return;
            }
        }

        PrintPacket(dateTime, srcMac, dstMac, dataLen, srcIp, dstIp, srcPort, dstPort, rawPacket);
        _packetIndex++;
        if (_packetIndex != _options.NumOfPacketsToDisplay) {
            Console.WriteLine();
            return;
        }
        _adapter?.Close();
        Environment.Exit(0);
    }

    private static Options CorrectOptions(Options options)
    {
        if (options is { PortOption: { }, TcpOption: false, UdpOption: false })
        {
            options.TcpOption = true;
            options.UdpOption = true;
        }

        if (options is { MldOption: false, ArpOption: false, Icmp4Option: false, Icmp6Option: false, IgmpOption: false, NdpOption: false, TcpOption: false, UdpOption: false })
        {
            options.MldOption = true;
            options.NdpOption = true;
            options.TcpOption = true;
            options.UdpOption = true;
            options.ArpOption = true;
            options.Icmp4Option = true;
            options.Icmp6Option = true;
            options.IgmpOption = true;
        }
        return options;
    }

    public static (string srcMac, string dstMac) GetMacAddress(EthernetPacket ethernetHeader)
    {
        var srcMac = MacAddressToString(ethernetHeader.SourceHardwareAddress);
        var dstMac = MacAddressToString(ethernetHeader.DestinationHardwareAddress);
        return (srcMac, dstMac);
    }

    public static (string dateTime, int dataLen) GetDateTimeAndLen(PacketCapture pcap)
    {
        var dateTime = DateTimeToRcf3339(pcap.Header.Timeval.Date);
        var dataLen = pcap.Data.Length;
        return (dateTime, dataLen);
    }

    private static string DateTimeToRcf3339(DateTime dateTime)
    {
        if (dateTime.Kind == DateTimeKind.Utc) {
            dateTime = TimeZoneInfo.ConvertTime(dateTime, TimeZoneInfo.Local);
        }
        return dateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK");
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

            if (c is >= ' ' and <= '~')
            {
                Console.Write(c);
            }
            else
            {
                Console.Write(".");
            }

            if (index == 7)
            {
                Console.Write(" ");
            }
        }
    }

    private static void PrintOffset(int offset)
    {
        Console.Write("0x" + offset.ToString("x4") + ": ");
    }
}