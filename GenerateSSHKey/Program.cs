using System;
using System.Threading.Tasks;
using System.Text;
using Chilkat;
using Consul;

namespace GenerateSSHKey
{
    class Program
    {
        static async System.Threading.Tasks.Task Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            Chilkat.SshKey key = new Chilkat.SshKey();

            int numbits = 2048;
            int exponent = 65537;
            
            bool success = key.GenerateRsaKey(numbits, exponent);
            if (!success)
            {
                Console.WriteLine("Failed");
            }
            
            Console.WriteLine("Generating Private Key");
            Console.WriteLine(key.ToOpenSshPrivateKey(false));

            Console.WriteLine("Generating Public SSH KEY-1");
            Console.WriteLine(key.ToOpenSshPublicKey());

            Console.WriteLine("Generating Public SSH KEY-2");
            Console.WriteLine(key.ToOpenSshPublicKey());

            // Store the value in Consul KV
            using (var client = new ConsulClient())
            {
                var putPair = new KVPair("secretkey") 
                {
                    Value = Encoding.UTF8.GetBytes(key.ToOpenSshPublicKey())
                };

                var putAttempt = await client.KV.Put(putPair);

                if(putAttempt.Response)
                {
                    var getPair = await client.KV.Get("secretkey");
                    if (getPair.Response != null) 
                    {
                        Console.WriteLine("Getting Back the Stored String");
                        Console.WriteLine(Encoding.UTF8.GetString(getPair.Response.Value, 0, getPair.Response.Value.Length));
                    }
                }
            }
        }
    }
}
