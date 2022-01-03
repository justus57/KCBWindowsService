using Newtonsoft.Json;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using RestSharp;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Web.Script.Serialization;
using System.Xml;
using static KCBWindowsService.classes;

namespace KCBWindowsService
{
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }
        public static string Accesstoken { get; private set; }
        static string path = AppDomain.CurrentDomain.BaseDirectory + @"\Config.xml";
       

        protected override void OnStart(string[] args)
        {
            WebService.WriteLog("Service Started");

            Timer timer = new Timer();
            timer.Interval = Convert.ToDouble(WebService.GetConfigData("ServiceTimerInterval"));
            timer.Elapsed += new System.Timers.ElapsedEventHandler(this._timer_Tick);
            timer.Enabled = true;
            timer.Start();
            WebService.GetServiceConstants();
        }

        private void _timer_Tick(object sender, ElapsedEventArgs e)
        {
            WebService.WriteLog("Running..");
            try
            {
               
                // encrypt the data using gpg
                PGPEncryptDecrypt pgp = new PGPEncryptDecrypt();
                string passPhrase = "KCB!";
                string origFilePath = @"C:\Users\Admin2\Downloads\New folder\newbie.txt";
                string encryptedFilePath = @"C:\Users\Admin2\Downloads\New folder\";                
                string unencryptedFilePath = @"C:\Users\Admin2\Downloads\New folder\";               
                string publicKeyFile = @"C:\Users\Admin2\Downloads\New folder\dummy.pkr";
                string privateKeyFile = @"C:\Users\Admin2\Downloads\New folder\dummy.skr";
                pgp.Encrypt(origFilePath, publicKeyFile, encryptedFilePath);

                DirectoryInfo DirInfo = new DirectoryInfo(@"c:\test\");

                var filesInOrder = from f in DirInfo.EnumerateFiles()
                                   orderby f.CreationTime
                                   select f;

                foreach (var item in filesInOrder)
                {
                    
                    string ConversationID = string.Format("{0:yyyy-MM-ddTHH:mm:ss.FFFZ}", DateTime.UtcNow);

                    string token = Gettoken();
                    token = "Bearer " + token;
                    //SENDING INFORMATION TO API
                    var PrintCommand = new checksumBody
                    {
                        conversationId = ConversationID,
                        encryptedFile = encryptedFilePath,
                        fileName = item.FullName,
                        systemCode = GetConfigData("systemCode"),
                        serviceId = GetConfigData("serviceId")

                    };
                    JavaScriptSerializer js = new JavaScriptSerializer();
                    string body = js.Serialize(PrintCommand);

                    //Sending using restsharp
                    var client = new RestClient(GetConfigData("Apiurl"));
                    client.Timeout = -1;
                    var request = new RestRequest(Method.POST);
                    request.AddHeader("Accept", "application/json");
                    request.AddHeader("Content-Type", "application/json");
                    request.AddHeader("Authorization", token);
                    request.AddParameter("application/json", body, ParameterType.RequestBody);
                    IRestResponse response = client.Execute(request);


                }
            }
            catch (Exception es)
            {
                WebService.WriteLog(es.Message);
                WebService.WriteLog(es.InnerException.ToString());
            }

        }
        //gets token
        public static string Gettoken()
        {
            try
            {
                string KCBRESPONSE = null;

                string Username = GetConfigData("Username"); 
                string Password = GetConfigData("Password"); 
                string svcCredentials = Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(Username + ":" + Password));
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                string auth = "Basic " + svcCredentials;

                var client = new RestClient(GetConfigData("auth"));
                client.Timeout = -1;
                var request = new RestRequest(Method.POST);
                request.AddHeader("Content-Type", "application/json");
                request.AddHeader("Authorization", auth);
                IRestResponse response = client.Execute(request);
                KCBRESPONSE = response.Content;
                Console.WriteLine(response.Content);

                TokenResponse AccessTokenRequestResponse = JsonConvert.DeserializeObject<TokenResponse>(KCBRESPONSE);
                var Accesstoken = AccessTokenRequestResponse.access_token;
            }
            catch (Exception es)
            {
                WebService.WriteLog(es.Message);
                string innerEx = "";
                if (es.InnerException != null)
                    innerEx = es.InnerException.ToString();
            }
            return Accesstoken;
        }
        //gets details from config file
        public static string GetConfigData(string XMLNode)
        {
            string value = "";
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(path);
                XmlNode WebServiceNameNode = doc.GetElementsByTagName(XMLNode)[0];

                value = WebServiceNameNode.InnerText;
            }
            catch (Exception es)
            {
              WebService.WriteLog(es.Message);
            }
            return value;
        }    
        protected override void OnStop()
        {
            WebService.WriteLog("Service Stopped");
        }
    }
    internal class classes
    {
        public class TokenResponse
        {
            public string access_token { get; set; }
            public string expires_in { get; set; }
            public string refresh_token { get; set; }
            public string token_type { get; set; }
            public string scope { get; set; }
        }
        public class checksumBody
        {
            public string conversationId { get; set; }
            public string serviceId { get; set; }
            public string systemCode { get; set; }
            public string fileName { get; set; }
            public string encryptedFile { get; set; }
            public string fileStream { get; set; }
        }
    }
    public class PGPEncryptDecrypt
    {

        public PGPEncryptDecrypt()
        {

        }

        /**
        * A simple routine that opens a key ring file and loads the first available key suitable for
        * encryption.
        *
        * @param in
        * @return
        * @m_out
        * @
        */
        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);
            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            // iterate through the key rings.
            //
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                    {
                        return k;
                    }
                }
            }
            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /**
        * Search a secret key ring collection for a secret key corresponding to
        * keyId if it exists.
        *
        * @param pgpSec a secret key ring collection.
        * @param keyId keyId we want.
        * @param pass passphrase to decrypt secret key with.
        * @return
        */
        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
            if (pgpSecKey == null)
            {
                return null;
            }
            return pgpSecKey.ExtractPrivateKey(pass);
        }

        /**
        * decrypt the passed in message stream
        */
        private static void DecryptFile(Stream inputStream, Stream keyIn, char[] passwd, string defaultFileName, string pathToSaveFile)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            try
            {
                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;
                PgpObject o = pgpF.NextPgpObject();
                //
                // the first object might be a PGP marker packet.
                //
                if (o is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList)o;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
                }
                //
                // find the secret key
                //
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(keyIn));
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passwd);
                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }
                if (sKey == null)
                {
                    throw new ArgumentException("secret key for message not found.");
                }
                Stream clear = pbe.GetDataStream(sKey);
                PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                PgpObject message = plainFact.NextPgpObject();
                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData)message;
                    PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());
                    message = pgpFact.NextPgpObject();
                }

                if (message is PgpLiteralData)
                {

                    PgpLiteralData ld = (PgpLiteralData)message;
                    string outFileName = ld.FileName;
                    if (outFileName.Length == 0)
                    {
                        outFileName = defaultFileName;
                    }

                    Stream fOut = File.Create(pathToSaveFile + outFileName);
                    Stream unc = ld.GetInputStream();
                    Streams.PipeAll(unc, fOut);
                    fOut.Close();
                }
                else if (message is PgpOnePassSignatureList)
                {
                    throw new PgpException("encrypted message contains a signed message - not literal data.");
                }
                else
                {
                    throw new PgpException("message is not a simple encrypted file - type unknown.");
                }
                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        WebService.WriteLog("message failed integrity check");
                    }
                    else
                    {
                        WebService.WriteLog("message integrity check passed");
                    }
                }
                else
                {
                    WebService.WriteLog("no message integrity check");
                }
            }
            catch (PgpException es)
            {
                WebService.WriteLog(es.Message);
                string innerEx = "";
                if (es.InnerException != null)
                    innerEx = es.InnerException.ToString();
            }
        }

        private static void EncryptFile(Stream outputStream, string fileName, PgpPublicKey encKey, bool armor, bool withIntegrityCheck)
        {

            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }
            try
            {
                MemoryStream bOut = new MemoryStream();
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(
                CompressionAlgorithmTag.Zip);
                PgpUtilities.WriteFileToLiteralData(
                comData.Open(bOut),
                PgpLiteralData.Binary,
                new FileInfo(fileName));
                comData.Close();
                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                cPk.AddMethod(encKey);
                byte[] bytes = bOut.ToArray();
                Stream cOut = cPk.Open(outputStream, bytes.Length);
                cOut.Write(bytes, 0, bytes.Length);
                cOut.Close();
                if (armor)
                {
                    outputStream.Close();
                }
            }
            catch (PgpException es)
            {
                WebService.WriteLog(es.Message);
                string innerEx = "";
                if (es.InnerException != null)
                    innerEx = es.InnerException.ToString();

            }
        }
        public void Encrypt(string filePath, string publicKeyFile, string pathToSaveFile)
        {
            Stream keyIn, fos;
            keyIn = File.OpenRead(publicKeyFile);
            string[] fileSplit = filePath.Split('\\');
            string fileName = fileSplit[fileSplit.Length - 1];
            fos = File.Create(pathToSaveFile + fileName + ".asc");
            EncryptFile(fos, filePath, ReadPublicKey(keyIn), true, true);
            keyIn.Close();
            fos.Close();
        }
        public void Decrypt(string filePath, string privateKeyFile, string passPhrase, string pathToSaveFile)
        {
            Stream fin = File.OpenRead(filePath);
            Stream keyIn = File.OpenRead(privateKeyFile);
            DecryptFile(fin, keyIn, passPhrase.ToCharArray(), new FileInfo(filePath).Name + ".out", pathToSaveFile);
            fin.Close();
            keyIn.Close();
        }
    }
}
