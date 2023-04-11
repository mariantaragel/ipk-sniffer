using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ipk_sniffer;

public class PacketSniffer
{
    private static int _packetIndex;

    public static void SniffInterface(string interfaceName, int numOfPacketsToDisplay)
    {
        var interfaces = LibPcapLiveDeviceList.Instance;

        using var adapter = interfaces.SingleOrDefault(i => i.Interface.FriendlyName == interfaceName);
        if (adapter == null) {
            Console.Error.WriteLine($"Interface {interfaceName} not found.");
            Environment.Exit(1);
        }

        const string capFile = "tcp.pcapng";
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice(capFile);
        offlineAdapter.Open(DeviceModes.Promiscuous);
        while (offlineAdapter.GetNextPacket(out var pcap) == GetPacketStatus.PacketRead && _packetIndex < numOfPacketsToDisplay) {
            OnPacketArrival(pcap);
        }

        /*
        const int readTimeoutMilliseconds = 1000;
        adapter.Open(DeviceModes.Promiscuous, read_timeout: readTimeoutMilliseconds);

        while (adapter.GetNextPacket(out var pcap) == GetPacketStatus.PacketRead && _packetIndex < numOfPacketsToDisplay) {
            OnPacketArrival(pcap);
        }

        adapter.Close();
        */
    }

    private static void OnPacketArrival(PacketCapture pcap)
    {
        var dateTime = pcap.Header.Timeval.Date;
        var dataLen = pcap.Data.Length;
        var rawPacket = pcap.GetPacket();

        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ethernetPacket = packet.Extract<EthernetPacket>();
        var ipPacket = packet.Extract<IPPacket>();
        var tcpPacket = packet.Extract<TcpPacket>();

        if (tcpPacket != null)
        {
            var srcMac = ethernetPacket.SourceHardwareAddress.ToString().ToLower();
            var dstMac = ethernetPacket.DestinationHardwareAddress.ToString().ToLower();
            var srcIp = ipPacket.SourceAddress;
            var dstIp = ipPacket.DestinationAddress;
            int srcPort = tcpPacket.SourcePort;
            int dstPort = tcpPacket.DestinationPort;

            Console.WriteLine($"timestamp: {DateTimeToRfc3339(dateTime)}\n" +
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

    private static string DateTimeToRfc3339(DateTime dateTime)
    {
        var dateFullYear = dateTime.Year.ToString();
        var dateMonth = IntToString(dateTime.Month);
        var dateDay = IntToString(dateTime.Day);
        var fullDate = dateFullYear + "-" + dateMonth + "-" + dateDay;
        var timeHour = IntToString(dateTime.Hour);
        var timeMinute = IntToString(dateTime.Minute);
        var timeSecond = IntToString(dateTime.Second);
        var secFrac = "." + dateTime.Millisecond;
        var partialTime = timeHour + ":" + timeMinute + ":" + timeSecond + secFrac;
        var timeOffset = "";
        var fullTime = partialTime + timeOffset;
        return fullDate + "T" + fullTime;
    }

    private static string IntToString(int num)
    {
        if (num < 10) {
            return "0" + num;
        }

        return num.ToString();
    }

    private static void HexDump(byte[] bytes)
    {
        var value = 0;
        var offset = value.ToString("0x0000");
        Console.Write(offset + ": ");
        for (var i = 1; i <= bytes.Length; i++)
        {
            var hex = BitConverter.ToString(bytes[(i - 1)..i]);
            if (i % 16 == 0)
            {
                Console.WriteLine(hex);
                value += 16;
                Console.Write(value.ToString("0000x0") + ": ");
            }
            else {
                Console.Write(hex + " ");
            }
        }
    }
}