using System;
using System.IO;
using System.Text;
using Moss.Sdk;

class Program
{
    static void Main(string[] args)
    {
        string canonical = "{\"event\":\"agent.action\",\"agent_id\":\"aaaa5555-0000-0000-0000-000000000001\",\"ts\":\"2026-06-05T05:00:00Z\",\"payload\":{\"k\":\"v\"}}";
        byte[] payload = Encoding.UTF8.GetBytes(canonical);
        string[] signers = {"ts", "go", "java", "dotnet", "python"};
        string baseDir = "/tmp/moss-crosslang";
        foreach (string signer in signers)
        {
            byte[] pk = File.ReadAllBytes(Path.Combine(baseDir, signer + ".pk"));
            byte[] sig = File.ReadAllBytes(Path.Combine(baseDir, signer + ".sig"));
            bool valid = MossSdk.Verify(payload, pk, sig);
            Console.WriteLine($"{signer} signed -> dotnet verified: {(valid ? "PASS" : "FAIL")}");
        }
    }
}
