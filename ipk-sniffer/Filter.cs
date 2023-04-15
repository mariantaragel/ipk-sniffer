namespace ipk_sniffer;

public class Filter
{
    public string FilterString = string.Empty;

    public string OptionsToString(Options options)
    {
        if (options.ArpOption)
        {
            FilterString = AddFilterOption("arp");
        }
        if (options.TcpOption)
        {
            FilterString = AddFilterOption("tcp");
        }
        if (options.UdpOption)
        {
            FilterString = AddFilterOption("udp");
        }
        if (options.Icmp4Option)
        {
            FilterString = AddFilterOption("icmp");
        }
        if (options.Icmp6Option)
        {
            FilterString = AddFilterOption("icmp6");
        }
        if (options.IgmpOption)
        {
            FilterString = AddFilterOption("igmp");
        }
        if (options.MldOption)
        {
            FilterString = AddFilterOption("ip6 multicast");
        }
        if (options.NdpOption)
        {
            FilterString = AddFilterOption("icmp6[icmp6type] >= 133 and icmp6[icmp6type] <= 137");
        }
        if (options.PortOption != null)
        {
            FilterString += " port " + options.PortOption;
        }
        return FilterString;
    }

    private string AddFilterOption(string filterOption)
    {
        if (FilterString == string.Empty)
        {
            return filterOption;
        }
        return FilterString + " or " + filterOption;
    }
}