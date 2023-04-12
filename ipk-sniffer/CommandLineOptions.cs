using System.CommandLine;

namespace ipk_sniffer;

public class CommandLineOptions
{
    public Option<string?> InterfaceOption;
    public Option<int> NumOption;
    public Option<bool> TcpOption;
    public Option<bool> UdpOption;
    public Option<int?> PortOption;
    public Option<bool> Icmp4Option;
    public Option<bool> Icmp6Option;
    public Option<bool> ArpOption;
    public Option<bool> NdpOption;
    public Option<bool> IgmpOption;
    public Option<bool> MldOption;

    public CommandLineOptions()
    {
        InterfaceOption = CreateInterfaceOption();
        NumOption = CreateNumOption();
        TcpOption = CreateTcpOption();
        UdpOption = CreateUdpOption();
        PortOption = CreatePortOption();
        Icmp4Option = CreateIcmp4Option();
        Icmp6Option = CreateIcmp6Option();
        ArpOption = CreateArpOption();
        NdpOption = CreateNdpOption();
        IgmpOption = CreateIgmpOption();
        MldOption = CreateMldOption();
    }

    public RootCommand CreateRootCommand()
    {
        var rootCommand = new RootCommand("Network sniffer");
        rootCommand.AddOption(InterfaceOption);
        rootCommand.AddOption(NumOption);
        rootCommand.AddOption(TcpOption);
        rootCommand.AddOption(UdpOption);
        rootCommand.AddOption(PortOption);
        rootCommand.AddOption(Icmp4Option);
        rootCommand.AddOption(Icmp6Option);
        rootCommand.AddOption(ArpOption);
        rootCommand.AddOption(NdpOption);
        rootCommand.AddOption(IgmpOption);
        rootCommand.AddOption(MldOption);
        return rootCommand;
    }

    public static Option<int> CreateNumOption()
    {
        var numOption = new Option<int>(name: "-n", description: "Number of packets to display", getDefaultValue: () => 1)
        {
            ArgumentHelpName = "num"
        };
        return numOption;
    }

    public static Option<int?> CreatePortOption()
    {
        var portOption = new Option<int?>(name: "-p", description: "Filter TCP/UDP based on port number")
        {
            ArgumentHelpName = "port"
        };
        return portOption;
    }

    public static Option<string?> CreateInterfaceOption()
    {
        var interfaceOption = new Option<string?>(name: "--interface", description: "Interface to sniff")
        {
            ArgumentHelpName = "interface",
            Arity = ArgumentArity.ZeroOrOne
        };
        interfaceOption.AddAlias("-i");
        return interfaceOption;
    }

    public static Option<bool> CreateTcpOption()
    {
        var tcpOption = new Option<bool>(name: "--tcp", description: "Display TCP segments")
        {
            ArgumentHelpName = "tcp"
        };
        tcpOption.AddAlias("-t");
        return tcpOption;
    }

    public static Option<bool> CreateUdpOption()
    {
        var tcpOption = new Option<bool>(name: "--udp", description: "Display UDP segments")
        {
            ArgumentHelpName = "UDP"
        };
        tcpOption.AddAlias("-u");
        return tcpOption;
    }

    public static Option<bool> CreateIcmp4Option()
    {
        var icmp4Option = new Option<bool>(name: "--icmp4", description: "Display ICMPv4 packets")
        {
            ArgumentHelpName = "ICMPv4"
        };
        return icmp4Option;
    }

    public static Option<bool> CreateIcmp6Option()
    {
        var icmp6Option = new Option<bool>(name: "--icmp6", description: "Display ICMPv6 echo request/response")
        {
            ArgumentHelpName = "ICMPv6"
        };
        return icmp6Option;
    }

    public static Option<bool> CreateArpOption()
    {
        var arpOption = new Option<bool>(name: "--arp", description: "Display ARP frames")
        {
            ArgumentHelpName = "ARP"
        };
        return arpOption;
    }

    public static Option<bool> CreateNdpOption()
    {
        var ndpOption = new Option<bool>(name: "--ndp", description: "Display ICMPv6 NDP packets")
        {
            ArgumentHelpName = "NDP"
        };
        return ndpOption;
    }

    public static Option<bool> CreateIgmpOption()
    {
        var igmpOption = new Option<bool>(name: "--igmp", description: "Display IGMP packets")
        {
            ArgumentHelpName = "IGMP"
        };
        return igmpOption;
    }

    public static Option<bool> CreateMldOption()
    {
        var mldOption = new Option<bool>(name: "--mld", description: "Display MLD packets")
        {
            ArgumentHelpName = "MLD"
        };
        return mldOption;
    }
}