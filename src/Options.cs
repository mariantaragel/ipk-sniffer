namespace ipk_sniffer;

public class Options
{
    public string? InterfaceName { get; set; }
    public int NumOfPacketsToDisplay { get; set; }
    public bool TcpOption { get; set; }
    public bool UdpOption { get; set; }
    public int? PortOption { get; set; }
    public bool Icmp4Option { get; set; }
    public bool Icmp6Option { get; set; }
    public bool ArpOption { get; set; }
    public bool NdpOption { get; set; }
    public bool IgmpOption { get; set; }
    public bool MldOption { get; set; }
}