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

        var rootCommand = new RootCommand("Network sniffer");
        rootCommand.AddOption(interfaceOption);

        rootCommand.SetHandler(interfaceOptionValue =>
        {
            if (interfaceOptionValue == null) {
                NetworkInterfaces.DisplayInterfaces();
            }
            else {
                NetworkInterfaces.DisplayInterfaces();
                Packet.CapturePcap(interfaceOptionValue);
            }
        }, interfaceOption);

        await rootCommand.InvokeAsync(args);
    }

    private static void MyHandler(object? sender, ConsoleCancelEventArgs args) => Environment.Exit(0);
}