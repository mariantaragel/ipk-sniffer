using System.CommandLine;

namespace ipk_sniffer;

internal class Program
{
    private static async Task Main(string[] args)
    {
        Console.CancelKeyPress += new ConsoleCancelEventHandler(MyHandler);

        var interfaceOption = new Option<string?>(name: "--interface", description: "Interface to sniff")
        {
            ArgumentHelpName = "interface",
            Arity = ArgumentArity.ZeroOrOne
        };
        interfaceOption.AddAlias("-i");

        var numOption = new Option<int>(name: "-n", description: "Number of packets to display", getDefaultValue: () => 1)
        {
            ArgumentHelpName = "num"
        };

        var rootCommand = new RootCommand("Network sniffer");
        rootCommand.AddOption(interfaceOption);
        rootCommand.AddOption(numOption);

        rootCommand.SetHandler((interfaceOptionValue, numOptionValue) =>
        {
            if (interfaceOptionValue == null) {
                NetworkInterfaces.DisplayInterfaces();
            }
            else {
                PacketSniffer.SniffInterface(interfaceOptionValue, numOptionValue);
            }
        }, interfaceOption, numOption);

        await rootCommand.InvokeAsync(args);
    }

    private static void MyHandler(object? sender, ConsoleCancelEventArgs args) => Environment.Exit(0);
}