using System;
using System.IO;
using System.Reflection;
using UniDsproc.DataModel;
using UniDsproc.SignatureProcessor;

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
						case ProgramFunction.Sign: //check!
							Console.WriteLine(sign(a).ToJsonString());
							break;
						case ProgramFunction.Verify:
							Console.WriteLine(verify(a).ToJsonString());
							break;
						case ProgramFunction.Extract: //check!
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
						$"		Determines what signature should be processed\n" +
						$"		Possible values : " +
						$"		  <smev2_base.detached>, <smev2_charge.enveloped>, " +
						$"		  <smev2_sidebyside.detached>, <smev3_base.detached>, " +
						$"		  <smev3_sidebyside.detached>, <smev3_ack>, <sig.detached>\n\n" +
						$"  node_id\n" +
						$"		String value of <Id> attribute of the node to be signed\n" +
						$"		Default value : 'ID_SIGN'\n\n" +
						$"  thumbprint [*:sign]\n" +
						$"		Signature certificate thumbprint\n\n" +
						$"  cer_file\n" +
						$"		Certificate file path for signature verification\n" +
						$"		If <thumbprint> key used - this key is ignored while\n" +
						$"		'verify' option selected\n\n" +
						$"  ds\n" +
						$"		Add ds: namespace prefix to <Signature> and descendants\n" +
						$"		Can not be verified by this program\n" +
						$"		Possible values : 'true', 'false', '1', '0', 'on', 'off'\n" +
						$"		Default value : 'false' \n\n" +
						$"  ignore_expired\n" +
						$"		Do not check certificate for expiration before signing\n" +
						$"		If 'false' and certificate is expired - error returned\n" +
						$"		Possible values : 'true', 'false', '1', '0', 'on', 'off'\n" +
						$"		Default value : 'false' \n\n" +
						$"  certificate_source [*:verify, verifyAndExtract]\n" +
						$"		Sets the source from which to extract the certificate\n" +
						$"		Possible values : 'xml', 'base64', 'cer'" +
						$"";
			Console.WriteLine(help);
			
		}
		#endregion

		#region [FUNCTIONS]
		private static StatusInfo sign(ArgsInfo args) {
			try {
				string signedData = SignatureProcessor.Signing.Sign(args.SigType, args.CertThumbprint, args.InputFile,
																	args.AssignDsInSignature, args.NodeId, args.IgnoreExpiredCert);
				File.WriteAllText(args.OutputFile, signedData);
				return new StatusInfo($"OK. Signed file path: {args.OutputFile}");
			} catch (Exception e) {
				return new StatusInfo(new ErrorInfo(ErrorCodes.SigningFailed,ErrorType.Signing,$"{e.Message}"));
			}
		}

		private static StatusInfo verify(ArgsInfo args) {
			try {
				bool isValid = SignatureProcessor.Verification.VerifySignature(
					args.SigType,
					args.InputFile,
					args.CertLocation == Verification.CertificateLocation.CerFile ? args.CertFilePath : null,
					args.CertLocation == Verification.CertificateLocation.Thumbprint ? args.CertThumbprint : null,
					args.NodeId
				);
				if (isValid) {
					return new StatusInfo(new ResultInfo("Signature is correct", true));
				} else {
					return new StatusInfo(new ResultInfo("Signature is invalid", false));
				}
			} catch (Exception e) {
				return new StatusInfo(new ErrorInfo(ErrorCodes.VerificationFailed, ErrorType.SignatureVerification, e.Message));
			}
		}

		private static StatusInfo extract(ArgsInfo args) {
			StatusInfo si = new StatusInfo(new ErrorInfo(ErrorCodes.UnknownException,ErrorType.CertificateExtraction, "Unknown certificate extraction exception"));
			try {
				si = new StatusInfo(new ResultInfo(SignatureProcessor.CertificateProcessing.CertificateToSerializableCertificate(args.CertSource, args.InputFile, args.NodeId)));
			} catch (Exception e) {
				si = new StatusInfo(new ErrorInfo(ErrorCodes.CertificateExtractionException, ErrorType.CertificateExtraction, e.Message));
			}
			
			return si;
		}

		private static StatusInfo verifyAndExtract(ArgsInfo args) {
			StatusInfo si = verify(args);
			if (!si.IsError) {
				if (si.Result.SignatureIsCorrect.HasValue && si.Result.SignatureIsCorrect.Value) {
					args.CertSource = CertificateSource.Xml;
					si = extract(args);
				}
			}
			return si;
		}
		#endregion

	}
}
