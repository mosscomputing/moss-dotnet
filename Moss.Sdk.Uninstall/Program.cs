using System;

class Program
{
    static int Main(string[] args)
    {
        bool dryRun = false;
        foreach (string arg in args)
        {
            if (arg == "--dry-run")
            {
                dryRun = true;
            }
        }

        Console.WriteLine("MOSS Uninstall Helper for moss-dotnet");
        Console.WriteLine("----------------------------------------");
        if (dryRun)
        {
            Console.WriteLine("[DRY-RUN MODE]");
        }

        Console.Write(@"
MANUAL CLEANUP CHECKLIST

[ ] Revoke/rotate MOSS credentials in the MOSS console (API keys / agent capability tokens)
[ ] Remove the Moss.Sdk dependency:
      dotnet remove package Moss.Sdk
[ ] Remove imports of ""Moss.Sdk"" (using Moss.Sdk;) from your .cs files
[ ] Remove config files: rm -f .moss.yml moss_config.json moss.config.js
[ ] Unset MOSS_* environment variables
[ ] CI/CD: remove MOSS_* secrets and setup steps from GitHub Actions / CI
[ ] Docker: remove MOSS_* ENV lines and the MOSS dependency from Dockerfiles
[ ] Docs: update README / setup guides that reference MOSS
");
        Console.WriteLine("\nChecklist printed. Complete the steps above manually.");
        return 0;
    }
}
