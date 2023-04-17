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
        TcpOption = CreateFlag("--tcp", "TCP", "Display TCP segments", "-t");
        UdpOption = CreateFlag("--udp", "UDP", "Display UDP segments", "-u");
        PortOption = CreatePortOption();
        Icmp4Option = CreateFlag("--icmp4", "ICMPv4", "Display ICMPv4 packets", string.Empty);
        Icmp6Option = CreateFlag("--icmp6", "ICMPv6", "Display ICMPv6 echo request/response", string.Empty);
        ArpOption = CreateFlag("--arp", "ARP", "Display ARP frames", string.Empty);
        NdpOption = CreateFlag("--ndp", "NDP", "Display ICMPv6 NDP packets", string.Empty);
        IgmpOption = CreateFlag("--igmp", "IGMP", "Display IGMP packets", string.Empty);
        MldOption = CreateFlag("--mld", "MLD", "Display ICMPv6 MLD packets", string.Empty);
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

    private static Option<int> CreateNumOption()
    {
        var numOption =
            new Option<int>(name: "-n", description: "Number of packets to display", getDefaultValue: () => 1)
            {
                ArgumentHelpName = "num"
            };
        return numOption;
    }

    private static Option<int?> CreatePortOption()
    {
        var portOption = new Option<int?>(name: "-p", description: "Filter TCP/UDP based on port number")
        {
            ArgumentHelpName = "port"
        };
        return portOption;
    }

    private static Option<string?> CreateInterfaceOption()
    {
        var interfaceOption = new Option<string?>(name: "--interface", description: "Interface to sniff")
        {
            ArgumentHelpName = "interface",
            Arity = ArgumentArity.ZeroOrOne
        };
        interfaceOption.AddAlias("-i");
        return interfaceOption;
    }

    private static Option<bool> CreateFlag(string name, string helpName, string description, string alias)
    {
        var flagOption = new Option<bool>(name: name, description: description)
        {
            ArgumentHelpName = helpName
        };
        if (alias != string.Empty) {
            flagOption.AddAlias(alias);
        }
        return flagOption;
    }
}