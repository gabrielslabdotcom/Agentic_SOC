// Wazuh on Windows runs active-response programs as .exe files.
// Build once, then copy to network-isolation.exe and network-deisolation.exe.
// The executable name selects the matching .ps1 in the same directory.
//
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:network-isolation.exe ar-launcher.cs
//   copy /Y network-isolation.exe network-deisolation.exe

using System;
using System.Diagnostics;
using System.IO;

class ArLauncher
{
    static int Main()
    {
        string dir = AppDomain.CurrentDomain.BaseDirectory;
        string exe = Path.GetFileNameWithoutExtension(Process.GetCurrentProcess().MainModule.FileName);
        string script = Path.Combine(dir, exe + ".ps1");
        var psi = new ProcessStartInfo();
        psi.FileName = "powershell.exe";
        psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + script + "\"";
        psi.WorkingDirectory = dir;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        try
        {
            Process process = Process.Start(psi);
            if (process == null)
            {
                return 1;
            }
            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Exception ex)
        {
            try
            {
                File.AppendAllText(
                    Path.Combine(dir, "ar-launcher.log"),
                    DateTime.Now.ToString("s") + " " + ex + Environment.NewLine);
            }
            catch
            {
            }
            return 1;
        }
    }
}
