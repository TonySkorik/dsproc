using System;
using System.Collections.Generic;
using System.IO;
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
						Console.WriteLine(sign(a).ToJsonString());
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
		private static StatusInfo sign(ArgsInfo args) {
			try {
				string signedData = SignatureProcessor.Signing.Sign(args.SigMode, args.CertThumbprint, args.InputFile,
																	args.AssignDsInSignature, args.NodeId);
				File.WriteAllText(args.OutputFile, signedData);
				return new StatusInfo($"OK. Signed file path: {args.OutputFile}");
			} catch (Exception e) {
				return new StatusInfo(new ErrorInfo(ErrorCodes.SigningFailed,ErrorType.Signing,$"Signing failed! Message: <{e.Message}>"));
			}
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
