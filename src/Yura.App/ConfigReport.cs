using Yura.App.Services;

namespace Yura.App;

/// <summary>
/// Prints where Yura keeps its configuration and secrets.
/// </summary>
/// <remarks>
/// Run with <c>--config-report</c>. "Where did my settings go?" and "is my password
/// actually saved anywhere?" are the first two questions in any support conversation, and
/// both should be answerable without reading source or guessing at XDG rules.
/// </remarks>
internal static class ConfigReport
{
    public static int Run()
    {
        var store = new ConfigStore();
        var secrets = new SecretToolSecretStore();

        Console.WriteLine($"config directory : {store.Directory}");
        Console.WriteLine($"config file      : {store.FilePath}");
        Console.WriteLine($"file exists      : {File.Exists(store.FilePath)}");
        Console.WriteLine($"XDG_CONFIG_HOME  : {Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") ?? "(unset, using ~/.config)"}");
        Console.WriteLine($"secret store     : {secrets.Description}");

        if (File.Exists(store.FilePath))
        {
            Console.WriteLine($"permissions      : {File.GetUnixFileMode(store.FilePath)}");
            var (document, warning) = store.Load();
            Console.WriteLine($"format version   : {document.Version}");
            Console.WriteLine($"proxies          : {document.Proxies.Count}");
            Console.WriteLine($"persistent rules : {document.Rules.Count}");
            if (warning is not null)
            {
                Console.WriteLine($"warning          : {warning}");
            }
        }

        return 0;
    }
}
