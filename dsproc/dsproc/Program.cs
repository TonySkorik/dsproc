using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using dsproc.DataModel;

namespace dsproc {
	class Program {
		private static void Main(string[] args) {
			ArgsInfo a = new ArgsInfo(args);
			if (a.Ok) {
				//args successfully loaded - continue
			} else {
				Console.WriteLine(a.InitError.ToJsonString());
				//args loading error - break, report error
			}
			Console.ReadKey();
		}
		
	}
}
