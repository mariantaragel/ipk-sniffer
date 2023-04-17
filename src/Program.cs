using System.CommandLine;

namespace ipk_sniffer;

internal class Program
{
    private static async Task Main(string[] args)
    {
        Console.CancelKeyPress += MyHandler;

        var commandLineOptions = new CommandLineOptions();
        var rootCommand = commandLineOptions.CreateRootCommand();

        rootCommand.SetHandler(options =>
        {
            if (options.InterfaceName == null) {
                NetworkInterfaces.DisplayInterfaces();
            }
            else {
                PacketSniffer.SniffInterface(options);
            }
        }, new OptionBinder(commandLineOptions) );

        await rootCommand.InvokeAsync(args);
    }

    private static void MyHandler(object? sender, ConsoleCancelEventArgs args) => Environment.Exit(0);
}