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
        var filter = new Filter();
        var options = new Options()
        {
            TcpOption = true
        };
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("tcp.pcapng");
        
        offlineAdapter.Open(DeviceModes.Promiscuous);
        filter.OptionsToString(options);
        offlineAdapter.Filter = filter.FilterString;

        // Exercise
        offlineAdapter.GetNextPacket(out var pcap);
        var (dateTime, dataLen) = PacketSniffer.GetDateTimeAndLen(pcap);
        
        // Verify
        Assert.Equal("2020-07-23T02:05:24.234Z", dateTime);
        Assert.Equal(66, dataLen);
    }

    [Fact]
    public void Test_Get_MacAddress()
    {
        // Setup
        var filter = new Filter();
        var options = new Options()
        {
            UdpOption = true
        };
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("udp.pcapng");

        offlineAdapter.Open(DeviceModes.Promiscuous);
        filter.OptionsToString(options);
        offlineAdapter.Filter = filter.FilterString;

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
        var filter = new Filter();
        var options = new Options()
        {
            Icmp4Option = true
        };
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("icmpv4.pcap");

        offlineAdapter.Open(DeviceModes.Promiscuous);
        filter.OptionsToString(options);
        offlineAdapter.Filter = filter.FilterString;

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
        var filter = new Filter();
        var options = new Options()
        {
            Icmp6Option = true
        };
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("icmpv6.pcap");

        offlineAdapter.Open(DeviceModes.Promiscuous);
        filter.OptionsToString(options);
        offlineAdapter.Filter = filter.FilterString;

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
        var filter = new Filter();
        var options = new Options()
        {
            PortOption = 443,
            TcpOption = true
        };
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("filter.pcapng");

        offlineAdapter.Open(DeviceModes.Promiscuous);
        filter.OptionsToString(options);
        offlineAdapter.Filter = filter.FilterString;

        // Exercise
        Assert.Equal(GetPacketStatus.PacketRead, offlineAdapter.GetNextPacket(out var pcap));
        var rawPacket = pcap.GetPacket();
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var tcpHeader = packet.Extract<TcpPacket>();
        var srcPort = tcpHeader.SourcePort;
        var dstPort = tcpHeader.DestinationPort;

        // Verify
        Assert.Equal(64236, srcPort);
        Assert.Equal(443, dstPort);
    }

    [Fact]
    public void Test_Filter_Ndp()
    {
        // Setup
        var filter = new Filter();
        var options = new Options()
        {
            NdpOption = true,
            NumOfPacketsToDisplay = 8
        };
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("filter1.pcapng");

        offlineAdapter.Open(DeviceModes.Promiscuous);
        filter.OptionsToString(options);
        offlineAdapter.Filter = filter.FilterString;

        // Exercise & Verify
        for (int i = 0; i < options.NumOfPacketsToDisplay; i++)
        {
            Assert.Equal(GetPacketStatus.PacketRead, offlineAdapter.GetNextPacket(out var pcap));
            var rawPacket = pcap.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var icmpV6Header = packet.Extract<IcmpV6Packet>();
            Assert.InRange((int)icmpV6Header.Type, 133, 137);
        }
    }

    [Fact]
    public void Test_Filter_Mld()
    {
        // Setup
        var filter = new Filter();
        var options = new Options()
        {
            MldOption = true,
            NumOfPacketsToDisplay = 14
        };
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("filter1.pcapng");

        offlineAdapter.Open(DeviceModes.Promiscuous);
        offlineAdapter.Open(DeviceModes.Promiscuous);
        filter.OptionsToString(options);

        // Exercise & Verify
        Assert.Equal(GetPacketStatus.PacketRead, offlineAdapter.GetNextPacket(out var pcap));
        var rawPacket = pcap.GetPacket();
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var icmpV6Header = packet.Extract<IcmpV6Packet>();
        Assert.NotNull(icmpV6Header);
    }
}