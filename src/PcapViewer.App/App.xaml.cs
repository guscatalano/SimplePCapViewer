using Microsoft.UI.Xaml;

namespace PcapViewer.App;

/// <summary>Application entry point. Creates and shows the main window.</summary>
public partial class App : Application
{
    private Window? _window;

    public App() => InitializeComponent();

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        var window = new MainWindow();
        _window = window;
        window.Activate();

        // Auto-open whatever paths were passed on the command line. The first .pcap/.pcapng/.cap
        // is opened as the capture; any .evtx/.etl args are attached. Example:
        //   SimplePCapViewer.exe demo.pcap demo.evtx schannel.etl
        var paths = Environment.GetCommandLineArgs().Skip(1).Where(File.Exists).ToList();
        if (paths.Count > 0)
            window.OpenFromCommandLineAsync(paths);
    }
}
