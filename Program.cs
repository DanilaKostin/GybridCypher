using System.Security.Cryptography;
using System.Text;

namespace ThirdConsole
{
    internal class Program
    {
        //Пытался создать класс для RSA, но вознила проблема с параметрами алгоритма.
        //А также на понятно немного из документации как их сгенерировать и просто взять и запомнить где нибудь.
        public class RSA
        {
            public static string Encrypt(string data, RSAParameters key)
            {

                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(key);
                    var byteData = Encoding.UTF8.GetBytes(data);
                    var encryptData = rsa.Encrypt(byteData, false);
                    return Convert.ToBase64String(encryptData);
                }
            }

            public static string Decrypt(string cipherText, RSAParameters key)
            {

                using (var rsa = new RSACryptoServiceProvider())
                {
                    var cipherByteData = Convert.FromBase64String(cipherText);
                    rsa.ImportParameters(key);

                    var encryptData = rsa.Decrypt(cipherByteData, false);
                    return Encoding.UTF8.GetString(encryptData);
                }
            }
        }
        
        public class AES
        {
            //Метод расшифровки АЕСом
            public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
            {
                // Check arguments.
                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException("plainText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");
                byte[] encrypted;

                // Create an Aes object
                // with the specified key and IV.
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;

                    // Create an encryptor to perform the stream transform.
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(plainText);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }

                // Return the encrypted bytes from the memory stream.
                return encrypted;
            }

            //Метод шифровки AESом
            public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
            {
                // Check arguments.
                if (cipherText == null || cipherText.Length <= 0)
                    throw new ArgumentNullException("cipherText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");

                // Declare the string used to hold
                // the decrypted text.
                string plaintext = null;

                // Create an Aes object
                // with the specified key and IV.
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;

                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {

                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                return plaintext;
            }
        }

        //Тут я пытался создать два клиента, у которых заранее заданы открытый и закрытый ключи, а также фи.
        //Столкнулся с проблемой, которую намного ниже описал.
        public class ClientA
        {
            //Если что, эти числа я взял из 1 лабы (просто скопировал)))
            public string Fi = "85342045788783896543994012088237595324922098693365361259357680396603852948873494929458588712534608823526194606663713071738418625438083223854141847576661103397150934206009756274454481630505395734621763141074095164255810005552272744886950350787842257743429836666476210712207028157234689524702244114802795406922181108737415177875733329564672240998871992932850617592678914883998622778534742538416183319450913917256406099318368113889538819186449132434349187077415317504642470145698998102969702912875098593113638446491084597911060078922501507290287471268534288505204107281872651082894301353830491106820112991033065973196400";
            public string PrivateKey = "66494829741123560203611289474126098131034485560632683356164836843431493896705803933015337617799844605689799834959248434240180085817704293869202303109824753001275745984300414967622230975211282094934206453423522868486575288594536248803182361813260513142292251262212179570905718238498779488012761692619848750397075066084465478782580169304599185491830639225073525924436696042840549959342043142195129047733980216460196702752799546801134891121775899634739019876823562688406402835060466494996480785263474619299293035747246897994980945079849327754744013456139678553521190333028178245082487393196886209223822415845227735198059";
            public ClientA()
            {

            }
        }

        public class ClientB 
        {
            public string Fi = "85342045788783896543994012088237595324922098693365361259357680396603852948873494929458588712534608823526194606663713071738418625438083223854141847576661103397150934206009756274454481630505395734621763141074095164255810005552272744886950350787842257743429836666476210712207028157234689524702244114802795406922181108737415177875733329564672240998871992932850617592678914883998622778534742538416183319450913917256406099318368113889538819186449132434349187077415317504642470145698998102969702912875098593113638446491084597911060078922501507290287471268534288505204107281872651082894301353830491106820112991033065973196400";
            public string OpenKey = "16328258959851659565547146618767236913400264116322228560573111846029773239433267034584948845903681102300649539";
            public ClientB()
            {

            }
        }

        //Хеш мд5, обычно записывается в виде 32ух 16-ричных чисел.
        static public string GetHash(byte[] input)
        {
            var str = Encoding.UTF8.GetString(input);
            var md5 = MD5.Create();
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(str));
            return Convert.ToBase64String(hash);
        }

        //Функция для строковой переменной
        static public string GetHash(string str)
        {
            var md5 = MD5.Create();
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(str));
            return Convert.ToHexString(hash); // ToBase64String(hash);
        }

        static void Main(string[] args)
        {
            string M = "Сообщение 123";

            //Вот эти переменные пойдут в файл
            byte[] IV, Key, Encrypted;

            using (Aes aes = Aes.Create())
            {
                IV = aes.IV; 
                Key = aes.Key;

                // Encrypt the string to an array of bytes.
                Encrypted = AES.EncryptStringToBytes_Aes(M, Key, IV);

                // Decrypt the bytes to a string.
                string roundtrip = AES.DecryptStringFromBytes_Aes(Encrypted, Key, IV);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", M);
                Console.WriteLine("Round Trip: {0}", roundtrip);
                Console.WriteLine("Round Trip: {0}", Key);
                Console.WriteLine("Round Trip: {0}", IV);
            }

            //RSA нужен для шифровки хеша сообщения (цифровая подпись), а также IV (инициализирующий вектор AES), Key, Encypted (сообщение-шифрованное симметричным методом AES) 
            //Затем это всё дело пишется в файл, второй "клиент" это считывает, проверяет подпись, расшифровывает. 
            //И у меня возникла проблема - как создать встроенный класс RSA с параметрами.
            //Вопрос - какие это параметры (напомню, это закр.ключ d, откр.ключ e, и функция эйлера ФИ.)
            //Откуда это гигантские цифры брать? Я так понял, их можно захардкодить в поля класса, или записать в файлик какой нибудь заранее
            //Так как эти параметры могут уже использоваться в канале связи, и клиенты их юзают уже. 
            var rsa = RSACryptoServiceProvider.Create(2048);

            //RSAParameters - это класс с параметрами для алгоритма RSA, но если начнёшь разбираться, увидешь, что полей там многовато
            //и не понято до конца, что это вообще
            

            //Вот мое видение всего, что нужно будет сделать:
            //1) Этот файлик с кодом - всего лишь тест на консоли, нужно будет переделывать в проект винд.формс, где просто записываем сообщение
            //Будут лейблы с выводом каких нибудь промежуточных результатов работы алгоритмов шифрования
            //Шифр-тексты, а также кнопки, например в правой части поле ввода сообщение, кнопка зашифровать,
            //Слева поле вывода шифра, кнопка расшифровать, и поле вывода расшифровки шифра (как Воронов говорил на паре, примерно)

            //2) Да, некоторые параметры, а именно цифровая подпись, IV, Key, Encrypted нужно записать в файл, потом при нажатии
            //На кнопку расшифровки оттуда считываем параметры и расшифровываем. Всё просто. НО вот проблема с долбаным RSA.
            //Как минимум для его работы нужно генерировать все параметы - и d, и e по новой каждый раз. 
            //Воронов не упоминал, да и на фотке нет этого, что нужно передавать d, или e по каналу связи. Это наталкивает на мысль
            //что эти параметры заранее известны, заданы у каждого клиента. Ну и тут два варианты -захардкодить их в поля, либо в файлик и потом считывать их.

            //3) В последий раз объясню логику всей этой гибридной системы)) :
            // КлиентА - имеет сообщение М, берет алгоритм AES применяет к сообщению M, 
            // в данном случае, !функция автоматом! генерирует IV и Key, на выходе имеем Encrypted.

            // КлиентА хеширует M -> h = H(M), где H - может быть мд5 или что то другое.

            //Шифрует по RSA -> IV, Key, Encrypted, h, и в случае h получаем цифровую подпись.
            
            //Запись в файл.

            //КлиентБ - читает из файла.
            //По RSA расшифровка цифровой подписи и encrypted, сравнение H(encrypted) и цифровой подписи. Если они равны, то всё ок, нет - то подстава))
            //Расшифровка остальных параметров и тк AES симметричный алгос, расшифровываем по тем же параметрам. Всё. Флаг в руки и работайте, братьяZ.


            /*            using (var rsa = new RSACryptoServiceProvider())
                        {
                            var par = new RSAParameters();

                            rsa.ImportParameters(key);
                            var byteData = Encoding.UTF8.GetBytes(data);
                            var encryptData = rsa.Encrypt(byteData, false);
                            return Convert.ToBase64String(encryptData);
                        }*/
        }
    }
}