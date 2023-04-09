using SharpPcap;
using SharpPcap.LibPcap;
using System.IO.Compression;

namespace ipk_sniffer;

public class Packet
{
    public static void DisplayInterfaces()
    {
        var adapters = LibPcapLiveDeviceList.Instance;

        if (adapters.Count < 1)
        {
            Console.WriteLine("No interfaces were found on this machine.");
            return;
        }

        foreach (var adapter in adapters)
        {
            Console.WriteLine(adapter.Name);
            Console.WriteLine(adapter.Description);
        }
    }

    public static void CapturePcap(string interfaceName)
    {
        Console.WriteLine(interfaceName);
        var inf = LibPcapLiveDeviceList.Instance;
        
        using var device = inf[3];
        Console.WriteLine(device.Name);

        device.OnPacketArrival += new PacketArrivalEventHandler(OnPacketArrival);
        
        int readTimeoutMilliseconds = 1000;
        device.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

        device.StartCapture();

        Console.ReadKey();

        device.StopCapture();

        Console.WriteLine(device.Statistics.ToString());
    }

    private static void OnPacketArrival(object sender, PacketCapture e)
    {
        Console.WriteLine(e.GetPacket().ToString());
    }
}