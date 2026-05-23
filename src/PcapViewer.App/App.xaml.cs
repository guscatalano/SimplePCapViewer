using Microsoft.UI.Xaml;

namespace PcapViewer.App;

/// <summary>Application entry point. Creates and shows the main window.</summary>
public partial class App : Application
{
    private Window? _window;

    public App() => InitializeComponent();

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _window = new MainWindow();
        _window.Activate();
    }
}
