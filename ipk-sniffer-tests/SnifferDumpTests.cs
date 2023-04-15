using ipk_sniffer;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ipk_sniffer_tests;

public class SnifferDumpTests
{
    [Fact]
    public void Test1()
    {
        // Setup
        ICaptureDevice offlineAdapter = new CaptureFileReaderDevice("tcp.pcapng");
        offlineAdapter.Open(DeviceModes.Promiscuous);

        // Exercise

        // Verify
    }
}