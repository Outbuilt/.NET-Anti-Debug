using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AuthGG
{
    class HashChecks
    {

        public static void CheckHashes() // Checks that all dll's have not been tampered with. If they have been tampered with (or the hash doesn't match for some reason), the application will not open.
        {

            if (GetHash("AUTHGG.dll") != "6F51148DF4AAA7AADC7BEF07F518157E" || GetHash("Outbuilt.dll") != "4DF6C8781E70C3A4912B5BE796E6D337" || GetHash("Newtonsoft.Json.dll") != "4DF6C8781E70C3A4912B5BE796E6D337") // When the DLLs are updated, they will have new hashes.
            {

                Process.Start(new ProcessStartInfo("cmd.exe", "/c START CMD /C \"ECHO AUTHGG.dll and / or Newtonsoft.Json.dll have tampered with! Application closed. && PAUSE\" ")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                Process.GetCurrentProcess().Kill();

            }

        }

        public static string GetHash(string file) // Calculates MD5 hash of a file.
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(file))
                {

                    var hash = md5.ComputeHash(stream);
                    string final = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
                    return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();

                }
            }

        }

    }
}