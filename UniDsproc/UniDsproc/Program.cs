using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using UniDsproc.DataModel;

namespace UniDsproc {
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
						Console.WriteLine(verify(a));
						break;
					case ProgramFunction.Extract:
						Console.WriteLine(extract(a));
						break;
					case ProgramFunction.VerifyAndExtract:
						Console.WriteLine(verifyAndExtract(a));
						break;
				}
			} else {
				Console.WriteLine(a.InitError.ToJsonString());
			}
		}

		#region [FUNCTIONS]
		private static StatusInfo sign(ArgsInfo args) {
			try {
				string signedData = SignatureProcessor.Signing.Sign(args.SigMode, args.CertThumbprint, args.InputFile,
																	args.AssignDsInSignature,args.IgnoreExpiredCert, args.NodeId);
				File.WriteAllText(args.OutputFile, signedData);
				return new StatusInfo($"OK. Signed file path: {args.OutputFile}");
			} catch (Exception e) {
				return new StatusInfo(new ErrorInfo(ErrorCodes.SigningFailed,ErrorType.Signing,$"{e.Message}"));
			}
		}

		private static StatusInfo verify(ArgsInfo args) {
			StatusInfo si = new StatusInfo("OK");

			return si;
		}

		private static StatusInfo extract(ArgsInfo args) {
			StatusInfo si = new StatusInfo("OK");

			return si;
		}

		private static StatusInfo verifyAndExtract(ArgsInfo args) {
			StatusInfo si = new StatusInfo("OK");
			si = verify(args);
			if (!si.IsError) {
				si = extract(args);
			}
			return si;
		}
		#endregion

	}
}
