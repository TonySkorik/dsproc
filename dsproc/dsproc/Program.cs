using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using dsproc.DataModel;

namespace dsproc {
	class Program {

		private static void Main(string[] args) {
			ArgsInfo a = new ArgsInfo(args);
			if (a.Ok) {
				//args successfully loaded - continue
				switch (a.Function) {
					case ProgramFunction.Sign:
						sign(a);
						break;
					case ProgramFunction.Verify:
						verify(a);
						break;
					case ProgramFunction.Extract:
						extract(a);
						break;
					case ProgramFunction.VerifyAndExtract:
						verifyAndExtract(a);
						break;
				}
			} else {
				Console.WriteLine(a.InitError.ToJsonString());
				//args loading error - break, report error
			}
			Console.ReadKey();
		}

		#region [FUNCTIONS]
		private static void sign(ArgsInfo args) {

		}

		private static bool verify(ArgsInfo args) {
			bool ret = false;

			return ret;
		}

		private static void extract(ArgsInfo args) {

		}

		private static void verifyAndExtract(ArgsInfo args) {
			if (verify(args)) {
				extract(args);
			}
		}
		#endregion

	}
}
