using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Chilkat;
using Consul;
using Jose;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GenerateSSHKey
{
    class Program
    {
        static async System.Threading.Tasks.Task Main(string[] args)
        {
            Chilkat.Global glob = new Chilkat.Global();
            glob.UnlockBundle("Anything for 30-day trial");

            Chilkat.Rsa rsaKey = new Chilkat.Rsa();

            rsaKey.GenerateKey(1024);
            var rsaPrivKey = rsaKey.ExportPrivateKeyObj();
            
            var rsaPublicKey = rsaKey.ExportPublicKeyObj();
            var rsaPublicKeyAsString = rsaKey.ExportPublicKey();

            Chilkat.JsonObject jwtHeader = new Chilkat.JsonObject();
            jwtHeader.AppendString("alg", "RS256");
            jwtHeader.AppendString("typ", "JWT");

            Chilkat.JsonObject claims = new Chilkat.JsonObject();
            claims.AppendString("Email", "nishantkumarajain@gmail.com");
            claims.AppendString("Test", "test1");

            Chilkat.Jwt jwt = new Chilkat.Jwt();
            
            string token = jwt.CreateJwtPk(jwtHeader.Emit(), claims.Emit(), rsaPrivKey);
            Console.WriteLine("This is the token generated");
            Console.WriteLine(token);

            // Verifying Token using Public Key
            Console.WriteLine(jwt.VerifyJwtPk(token, rsaPublicKey));
            Console.WriteLine(jwt.GetPayload(token));
            
            // Importing public key
            Chilkat.Rsa rsaExportedPublicKey = new Chilkat.Rsa();
            Console.WriteLine(rsaExportedPublicKey.ImportPublicKey(rsaPublicKeyAsString));
            Console.WriteLine(jwt.VerifyJwtPk(token, rsaExportedPublicKey.ExportPublicKeyObj()));
            
            // Store the value in Consul KV
            using (var client = new ConsulClient())
            {
                var putPair = new KVPair("secretkey") 
                {
                    Value = Encoding.UTF8.GetBytes(rsaPublicKeyAsString)
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
