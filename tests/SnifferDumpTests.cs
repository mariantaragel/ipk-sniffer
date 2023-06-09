using System.Net;
using ipk_sniffer;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ipk_sniffer_tests;

public class SnifferDumpTests
{
    [Fact]
    public void Test_Get_DateTime_And_DataLen()
    {
        // Setup
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("../../../../pcap/tcp.pcapng");
        offlineAdapter.Open(DeviceModes.Promiscuous);

        // Exercise
        offlineAdapter.GetNextPacket(out var pcap);
        var (dateTime, dataLen) = PacketSniffer.GetDateTimeAndLen(pcap);
        
        // Verify
        Assert.Equal("2020-07-23T04:05:24.234+02:00", dateTime);
        Assert.Equal(66, dataLen);
    }

    [Fact]
    public void Test_Get_MacAddress()
    {
        // Setup
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("../../../../pcap/udp.pcapng");
        offlineAdapter.Open(DeviceModes.Promiscuous);

        // Exercise
        offlineAdapter.GetNextPacket(out var pcap);
        var rawPacket = pcap.GetPacket();
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ethernetHeader = packet.Extract<EthernetPacket>();
        var (srcMac, dstMac) = PacketSniffer.GetMacAddress(ethernetHeader);

        // Verify
        Assert.Equal("62:36:be:ff:91:20", srcMac);
        Assert.Equal("5e:2c:af:2e:1e:51", dstMac);
    }

    [Fact]
    public void Test_Get_Ipv4Address()
    {
        // Setup
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("../../../../pcap/icmpv4.pcap");
        offlineAdapter.Open(DeviceModes.Promiscuous);

        // Exercise
        offlineAdapter.GetNextPacket(out var pcap);
        var rawPacket = pcap.GetPacket();
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ipHeader = packet.Extract<IPPacket>();
        var srcIp = ipHeader.SourceAddress;
        var dstIp = ipHeader.DestinationAddress;

        // Verify
        Assert.Equal(IPAddress.Parse("192.168.158.139"), srcIp);
        Assert.Equal(IPAddress.Parse("174.137.42.77"), dstIp);
    }

    [Fact]
    public void Test_Get_Ipv6Address()
    {
        // Setup
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("../../../../pcap/icmpv6.pcap");
        offlineAdapter.Open(DeviceModes.Promiscuous);

        // Exercise
        offlineAdapter.GetNextPacket(out var pcap);
        var rawPacket = pcap.GetPacket();
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ipHeader = packet.Extract<IPPacket>();
        var srcIp = ipHeader.SourceAddress;
        var dstIp = ipHeader.DestinationAddress;

        // Verify
        Assert.Equal(IPAddress.Parse("fe80::2a0:ccff:fed9:4175"), srcIp);
        Assert.Equal(IPAddress.Parse("ff02::2"), dstIp);
    }

    [Fact]
    public void Test_Get_Port()
    {
        // Setup
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("../../../../pcap/tcp.pcapng");
        offlineAdapter.Open(DeviceModes.Promiscuous);

        // Exercise
        Assert.Equal(GetPacketStatus.PacketRead, offlineAdapter.GetNextPacket(out var pcap));
        var rawPacket = pcap.GetPacket();
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var tcpHeader = packet.Extract<TcpPacket>();
        var srcPort = tcpHeader.SourcePort;
        var dstPort = tcpHeader.DestinationPort;

        // Verify
        Assert.Equal(7875, srcPort);
        Assert.Equal(2000, dstPort);
    }
}