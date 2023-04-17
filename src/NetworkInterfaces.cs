using System.Net.NetworkInformation;

namespace ipk_sniffer;

public class NetworkInterfaces
{
    public static void DisplayInterfaces()
    {
        var adapters = NetworkInterface.GetAllNetworkInterfaces();
        
        if (adapters.Length < 1)
        {
            Console.WriteLine("No network interfaces were found on this machine.");
            return;
        }
        
        foreach (var adapter in adapters)
        {
            Console.WriteLine(adapter.Name);
            Console.WriteLine($"  Description ............................. : {adapter.Description}");
            Console.WriteLine($"  Operational Status ...................... : {adapter.OperationalStatus}");
            Console.WriteLine($"  Network Interface Type .................. : {adapter.NetworkInterfaceType}");
        }
    }
}