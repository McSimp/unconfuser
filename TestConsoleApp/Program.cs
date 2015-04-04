using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestConsoleApp
{
    class Program
    {
        static void TestingFunction()
        {
            var t = 10;
            for (int i = 0; i < t; i++)
            {
                if (i == 5)
                {
                    Console.WriteLine("Hello Again!");
                    i++;
                }
            }
            t = 0;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Hello!");
            TestingFunction();
            Console.ReadLine();
        }
    }
}
