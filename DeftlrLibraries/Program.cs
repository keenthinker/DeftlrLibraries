using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DeftlrLibraries
{
    class Program
    {
        static void Main(string[] args)
        {
            var clientVerificationToken = "client verification token";
            var deftlrService = new DeftlrCryptoLib(clientVerificationToken);

            // search
            //deftlrService.Search("hello");
            //var response = deftlrService.Search("image").Print();

            // read
            //var sid = response.SID;
            //var message = deftlrService.Read(id).Print();
            // manually decrypt
            //var ch = new DeftlrCryptoHelper("token", message.IV, message.Salt);
            //var dmessage = ch.Decrypt(message.Content);
            //dmessage.Dump();

            // search and decode
            //deftlrService.SearchAndRead("hello", "deftlr").Print();
            //deftlrService.SearchAndRead("tag", "token").Print();
            //deftlrService.SearchAndRead("image", "deftlr").Print();
            //var r = deftlrService.SearchAndRead("tag", "token").Print();
            //File.WriteAllBytes(@"c:\temp\image.png", r.ImageContent);
            // search with non existing tag
            //deftlrService.SearchAndRead("hello1", "deftlr").Print();

            // new id
            //deftlrService.Id().Print();

            // delete 
            //deftlrService.Delete("tag", "token");

            // search by master
            //deftlrService.Master("").Print();

            // create item
            //deftlrService.Create("tag", "token", "a message");
            //deftlrService.Create("tag", "token", new FileInfo(@"c:\temp\image.png"));
        }
    }
}
