using System.CommandLine;
using System.CommandLine.Binding;

namespace ipk_sniffer;

public class OptionBinder : BinderBase<Options>
{
    private readonly Option<string?> _interfaceOption;
    private readonly Option<int> _numOption;
    private readonly Option<bool> _tcpOption;
    private readonly Option<bool> _udpOption;
    private readonly Option<int?> _portOption;
    private readonly Option<bool> _icmp4Option;
    private readonly Option<bool> _icmp6Option;
    private readonly Option<bool> _arpOption;
    private readonly Option<bool> _ndpOption;
    private readonly Option<bool> _igmpOption;
    private readonly Option<bool> _mldOption;

    public OptionBinder(CommandLineOptions commandLineOptions)
    {
        _interfaceOption = commandLineOptions.InterfaceOption;
        _numOption = commandLineOptions.NumOption;
        _tcpOption = commandLineOptions.TcpOption;
        _udpOption = commandLineOptions.UdpOption;
        _portOption = commandLineOptions.PortOption;
        _icmp4Option = commandLineOptions.Icmp4Option;
        _icmp6Option = commandLineOptions.Icmp6Option;
        _ndpOption = commandLineOptions.NdpOption;
        _igmpOption = commandLineOptions.IgmpOption;
        _mldOption = commandLineOptions.MldOption;
        _arpOption = commandLineOptions.ArpOption;
    }

    protected override Options GetBoundValue(BindingContext bindingContext) =>
        new Options
        {
            InterfaceName = bindingContext.ParseResult.GetValueForOption(_interfaceOption),
            NumOfPacketsToDisplay = bindingContext.ParseResult.GetValueForOption(_numOption),
            TcpOption = bindingContext.ParseResult.GetValueForOption(_tcpOption),
            UdpOption = bindingContext.ParseResult.GetValueForOption(_udpOption),
            PortOption = bindingContext.ParseResult.GetValueForOption(_portOption),
            Icmp4Option = bindingContext.ParseResult.GetValueForOption(_icmp4Option),
            Icmp6Option = bindingContext.ParseResult.GetValueForOption(_icmp6Option),
            NdpOption = bindingContext.ParseResult.GetValueForOption(_ndpOption),
            IgmpOption = bindingContext.ParseResult.GetValueForOption(_igmpOption),
            MldOption = bindingContext.ParseResult.GetValueForOption(_mldOption),
            ArpOption = bindingContext.ParseResult.GetValueForOption(_arpOption)
        };
}