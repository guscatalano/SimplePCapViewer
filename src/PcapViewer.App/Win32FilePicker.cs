using System.Runtime.InteropServices;
using System.Text;

namespace PcapViewer.App;

/// <summary>
/// Thin wrapper around the Win32 <c>GetOpenFileNameW</c> common dialog. Used instead
/// of <see cref="Windows.Storage.Pickers.FileOpenPicker"/> in places where the WinRT
/// picker is unreliable — notably right after a <c>ContentDialog</c> closes in
/// unpackaged WinUI 3, where the picker often silently fails to appear.
/// </summary>
internal static class Win32FilePicker
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct OPENFILENAME
    {
        public int      lStructSize;
        public IntPtr   hwndOwner;
        public IntPtr   hInstance;
        public string?  lpstrFilter;
        public string?  lpstrCustomFilter;
        public int      nMaxCustFilter;
        public int      nFilterIndex;
        public IntPtr   lpstrFile;
        public int      nMaxFile;
        public string?  lpstrFileTitle;
        public int      nMaxFileTitle;
        public string?  lpstrInitialDir;
        public string?  lpstrTitle;
        public int      Flags;
        public short    nFileOffset;
        public short    nFileExtension;
        public string?  lpstrDefExt;
        public IntPtr   lCustData;
        public IntPtr   lpfnHook;
        public string?  lpTemplateName;
        public IntPtr   pvReserved;
        public int      dwReserved;
        public int      FlagsEx;
    }

    private const int OFN_FILEMUSTEXIST = 0x00001000;
    private const int OFN_PATHMUSTEXIST = 0x00000800;
    private const int OFN_EXPLORER      = 0x00080000;
    private const int OFN_NOCHANGEDIR   = 0x00000008;

    [DllImport("comdlg32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetOpenFileNameW(ref OPENFILENAME ofn);

    /// <summary>
    /// Shows the Win32 file-open dialog. <paramref name="filter"/> uses the standard
    /// "Description\0*.ext;*.ext\0Description\0*.ext\0" format. Returns null if the
    /// user cancels.
    /// </summary>
    public static string? PickSingleFile(IntPtr owner, string title, string filter, string? initialDir = null)
    {
        // Filter strings use embedded NULs; pass the raw bytes-with-NULs string.
        const int bufSize = 32 * 1024;
        IntPtr fileBuf = Marshal.AllocHGlobal(bufSize * sizeof(char));
        try
        {
            // Zero the buffer.
            for (int i = 0; i < bufSize; i++)
                Marshal.WriteInt16(fileBuf, i * 2, 0);

            var ofn = new OPENFILENAME
            {
                lStructSize  = Marshal.SizeOf<OPENFILENAME>(),
                hwndOwner    = owner,
                lpstrFilter  = filter,
                nFilterIndex = 1,
                lpstrFile    = fileBuf,
                nMaxFile     = bufSize,
                lpstrTitle   = title,
                lpstrInitialDir = initialDir,
                Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR,
            };

            if (!GetOpenFileNameW(ref ofn))
                return null;   // user cancelled or dialog failed

            var sb = new StringBuilder(bufSize);
            for (int i = 0; i < bufSize; i++)
            {
                char c = (char)Marshal.ReadInt16(fileBuf, i * 2);
                if (c == '\0') break;
                sb.Append(c);
            }
            return sb.ToString();
        }
        finally
        {
            Marshal.FreeHGlobal(fileBuf);
        }
    }
}
