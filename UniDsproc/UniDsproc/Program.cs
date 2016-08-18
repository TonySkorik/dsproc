using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using UniDsproc.DataModel;

namespace UniDsproc {
	class Program {
		private static void Main(string[] args) {
			if (args.Length > 0) {
				if (args[0] == @"\?" || args[0] == @"?" || args[0] == "help") {
					showHelp();
					return;
				}
				ArgsInfo a = new ArgsInfo(args);
				if (a.Ok) {
					//args successfully loaded - continue
					switch (a.Function) {
						case ProgramFunction.Sign:
							Console.WriteLine(sign(a).ToJsonString());
							break;
						case ProgramFunction.Verify:
							Console.WriteLine(verify(a).ToJsonString());
							break;
						case ProgramFunction.Extract:
							Console.WriteLine(extract(a).ToJsonString());
							break;
						case ProgramFunction.VerifyAndExtract:
							Console.WriteLine(verifyAndExtract(a).ToJsonString());
							break;
					}
				} else {
					Console.WriteLine(new StatusInfo(a.InitError).ToJsonString());
				}
			} else {
				showHelp();
				return;
			}
		}

		#region [HELP MESSAGE]
		private static void showHelp() {
			string version = $"{Assembly.GetExecutingAssembly().GetName().Version.Major}.{Assembly.GetExecutingAssembly().GetName().Version.Minor}.{Assembly.GetExecutingAssembly().GetName().Version.Revision}";
			int l = 32;
			string help = $"[UniDSProc v{version}]\n" +
						$"{new String('-', l)}\n" +
						$" Call string: UniDsproc.exe <function> [keys] <input file> [output file]\n" +
						$"{new String('-', l)}\n" +
						$" FUNCTIONS: \n" +
						$"  sign\n" +
						$"\tSign file and save signed one to file\n\n" +
						$"  verify\n" +
						$"\tVerify file signature\n\n" +
						$"  extract\n" +
						$"\tExtract certificate from file signature and return as JSON\n\n" +
						$"  verifyAndExtract\n" +
						$"\tVerify file's signature and, if it's valid - extact\n\n" +
						$"{new String('-', l)}\n" +
						$" KEYS: \n" +
						$"  [*:<function>] - required when <function> is selected\n" +
						$"\n" +
						$"  signature_type [*:sign]\n" +
						$"		Determines what signature should be created\n" +
						$"		Possible values : 'detached', 'enveloped', 'sidebyside'\n\n" +
						$"  smev_mode\n" +
						$"		Determines which SMEV-specific transformations\n" +
						$"		should be applied\n" +
						$"		Possible values : '2', '3'\n" +
						$"		Default value : 2 \n" +
						$"		If <signature_type> is 'detached' this key is ignored\n\n" +
						$"  node_id\n" +
						$"		String value of <Id> attribute of the node to be signed\n" +
						$"		Default value : 'ID_SIGN'\n\n" +
						$"  node_name\n" +
						$"		String value of the node to be signed tag name\n" +
						$"		Default value : null\n" +
						$"		If <node_id> key used - this key is ignored\n\n" +
						$"  node_namespace\n" +
						$"		String value of the node to be signed tag name\n" +
						$"		If <node_id> key used - this key is ignored\n\n" +
						$"  thumbprint [*:sign,verify]\n" +
						$"		Signature certificate thumbprint\n\n" +
						$"  cer_file\n" +
						$"		Certificate file path for signature verification\n" +
						$"		If <thumbprint> key used - this key is ignored while\n" +
						$"		'verify' option selected\n\n" +
						$"  ds\n" +
						$"		Certificate file path for signature verification\n" +
						$"		Possible values : 'true', 'false', '1', '0', 'on', 'off'\n" +
						$"		Default value : 'false' \n\n" +
						$"  ignore_expired\n" +
						$"		Do not check certificate for expiration before signing\n" +
						$"		If 'false' and certificate is expired - error returned\n" +
						$"		Possible values : 'true', 'false', '1', '0', 'on', 'off'\n" +
						$"		Default value : 'false' \n\n" +
						$"";
			Console.WriteLine(help);
		}
		#endregion

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
			
			StatusInfo si = new StatusInfo(new ErrorInfo(ErrorCodes.UnknownException,ErrorType.CertificateExtraction, "Unknown certificate extraction exception"));
			try {
				X509Certificate2 cert = SignatureProcessor.CertificateProcessing.ReadCertificateFromXml(args.InputFile);
				si = new StatusInfo(new ResultInfo(cert));
			} catch (Exception e) {
				si = new StatusInfo(new ErrorInfo(ErrorCodes.CertificateExtractionException, ErrorType.CertificateExtraction, e.Message));
			}
			
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
