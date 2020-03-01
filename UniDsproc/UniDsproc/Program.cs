using System;
using System.IO;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Serilog;
using Space.CertificateSerialization;
using Space.Core;
using Space.Core.Configuration;
using Space.Core.Interfaces;
using Topshelf;
using UniDsproc.Api;
using UniDsproc.Configuration;
using UniDsproc.DataModel;

namespace UniDsproc
{
	internal class Program
	{
		private static string GetVersion =>
			$"{Assembly.GetExecutingAssembly().GetName().Version.Major}"
			+ $".{Assembly.GetExecutingAssembly().GetName().Version.Minor}"
			+ $".{Assembly.GetExecutingAssembly().GetName().Version.Build}"
			+ $".{Assembly.GetExecutingAssembly().GetName().Version.Revision}";
		private static string GetVersionName => "API-enabled";

		public static WebApiHost WebApiHost { get; private set; }

		private static void Main(string[] args)
		{
			if (args.Length > 0)
			{
				
				if (args[0] == @"\?" || args[0] == @"?" || args[0] == "help")
				{
					ShowHelp();
					return;
				}

				var configuration = GetConfiguration();
				InitializeLogger(configuration);
				WebApiHost = new WebApiHost(configuration);

				if (args[0] == "api")
				{ 
					ConfigureService(string.Empty);
				}

				if (args[0] == "install" 
					|| args[0] == "uninstall")
				{ 
					ConfigureService(args[0]);
					return;
				}

				ArgsInfo a = new ArgsInfo(args, false);
				var statusInfo = MainCore(a);
				Console.WriteLine(statusInfo.ToJsonString());
			}
			else
			{
				ShowHelp();
				return;
			}
		}

		#region Initialization methods

		private static void InitializeLogger(AppSettings settings)
		{
			var loggerConfig = new LoggerConfiguration()
				.WriteTo
				.File(settings.Logger.FilePath, settings.Logger.MinimumEventLevel)
				.WriteTo
				.Console();
			Log.Logger = loggerConfig.CreateLogger();
		}

		public static AppSettings GetConfiguration()
		{
			var configRoot = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();
			AppSettings ret = configRoot.Get<AppSettings>();
			return ret;
		}

		#endregion

		#region Web Api Service configuration methods

		private static void ConfigureService(string verb)
		{
			var host = HostFactory.New(
				x =>
				{
					x.Service<WebApiHost>(
						s =>
						{
							s.ConstructUsing(() => WebApiHost);
							s.WhenStarted(apiHost => apiHost.Start());
							s.WhenStopped(apiHost => apiHost.Stop());
						});
					x.RunAsLocalSystem();
					x.StartAutomatically();
					

					x.ApplyCommandLine(verb);
					x.SetDescription("UniDsProc signing service");
					x.SetDisplayName("UniDsProcApi");
					x.SetServiceName("UniDsProcApi");
				});
			
			var rc = host.Run();

			var exitCode = (int)Convert.ChangeType(rc, rc.GetTypeCode());
			Environment.ExitCode = exitCode;
		}

		#endregion

		public static StatusInfo MainCore(ArgsInfo args)
		{
			if (args.Ok)
			{
				switch (args.Function)
				{
					case ProgramFunction.Sign:
						return Sign(args);
					case ProgramFunction.Verify:
						return Verify(args);
					case ProgramFunction.Extract:
						return Extract(args);
					case ProgramFunction.VerifyAndExtract:
						return VerifyAndExtract(args);
				}
			}
			return new StatusInfo(args.InitError);
		}

		#region [HELP MESSAGE]
		private static void ShowHelp()
		{
			string version = $"{GetVersion} {GetVersionName}";
			var separator = $"{new string('-', 32)}\n";
			string ntt = "\n\t\t    ";
			string help = $"[UniDSProc v{version}]\n" +
				separator +
				$" Call string: UniDsproc.exe <function> [keys] <input file> [output file]\n" +
				separator +
				$" FUNCTIONS: \n" +
				$"  install \n" +
				$"\tInstall UniDsProc as a self-hosted web service (via Windows Services mechanism)\n\n" +
				$"  uninstall \n" +
				$"\tUninstall previously installed UniDsProc windows service\n\n" +
				$"  api \n" +
				$"\tRun UniDsProc in interactive web api mode (as a self hosted web server)\n\n" +
				$"  sign\n" +
				$"\tSign file and save signed one to file\n\n" +
				$"  verify\n" +
				$"\tVerify file signature\n\n" +
				$"  extract\n" +
				$"\tExtract certificate from file signature and return as JSON\n\n" +
				$"  verifyAndExtract\n" +
				$"\tVerify file's signature and, if it's valid - extract\n\n" +
				separator +
				$" KEYS: \n" +
				$"  [*:<function>] - required when <function> is selected\n" +
				$"\n" +
				$"  signature_type [*:sign]\n" +
				$"		Determines what signature should be processed\n" +
				$"		Suffixes:\n" +
				$"		    *.string* - string input\n" +
				$"		    *.bin* - binary input\n" +
				$"		    *.nocert* - no certificates included\n" +
				$"		    *.allcert* - whole certificate chain included\n" +
				$"		Possible values : " +
				$"{ntt}<smev2_base.detached>,{ntt}" +
				$"<smev2_charge.enveloped>,{ntt}" +
				$"<smev2_sidebyside.detached>,{ntt}" +

				$"{ntt}<smev3_base.detached>,{ntt}" +
				$"<smev3_sidebyside.detached>,{ntt}" +
				$"<smev3_ack>,{ntt}" +

				$"{ntt}<sig_detached> - signs binary content of the file provided, end certificate included,{ntt}" +
				$"<sig_detached.nocert>,{ntt}" +
				$"<sig_detached.allcert>,{ntt}" +

				$"{ntt}<pkcs7.string> - signs text content of the file provided (reads file in UTF-8), end certificate included,{ntt}" +
				$"<pkcs7.string.nocert>,{ntt}" +
				$"<pkcs7.string.allcert>,{ntt}" +

				$"{ntt}<rsa2048_sha256.string>,{ntt}" +
				$"<rsa_sha256.string>\n"
				+ $"\n" +

				$"  gost_flavor\n" +
				$"		Determines what gost type (flavor) should be used\n" +
				$"		Possible values : " +
				$"{ntt}<None>,{ntt}" +
				$"<Gost_Obsolete>,{ntt}" +
				$"<Gost2012_256>,{ntt}" +
				$"<Gost2012_512>\n"
				+ $"\n" +

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
				$"		Works only with following signature types : \n" +
				$"		'smev3_sidebyside.detached', 'smev3_base.detached', 'smev3_ack' \n" +
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

		private static StatusInfo Sign(ArgsInfo args)
		{
			ISigner signer = new Signer();
			try
			{
				string signedData = signer.Sign(
					args.SigType,
					args.GostFlavor,
					args.CertThumbprint,
					args.InputFile,
					args.AssignDsInSignature,
					args.NodeId,
					args.IgnoreExpiredCert);
				File.WriteAllText(args.OutputFile, signedData);
				return new StatusInfo($"OK. Signed file path: {args.OutputFile}");
			}
			catch (Exception e)
			{
				return new StatusInfo(new ErrorInfo(ErrorCodes.SigningFailed, ErrorType.Signing, $"{e.Message}"));
			}
		}

		private static StatusInfo Verify(ArgsInfo args)
		{
			try
			{
				ISignatureVerificator verificator = new SignatureVerificator();
				bool isValid = verificator.VerifySignature(
					args.SigType,
					args.InputFile,
					args.CertLocation == CertificateLocation.CerFile
						? args.CertFilePath
						: null,
					args.CertLocation == CertificateLocation.Thumbprint
						? args.CertThumbprint
						: null,
					args.NodeId
				);
				return isValid
					? new StatusInfo(new ResultInfo("Signature is correct", true))
					: new StatusInfo(new ResultInfo("Signature is invalid", false));
			}
			catch (Exception e)
			{
				return new StatusInfo(new ErrorInfo(ErrorCodes.VerificationFailed, ErrorType.SignatureVerification, e.Message));
			}
		}

		private static StatusInfo Extract(ArgsInfo args)
		{
			StatusInfo si;
			try
			{
				ICertificateSerializer serializer = new CertificateSerializer();
				si =
					new StatusInfo(
						new ResultInfo(
							serializer.CertificateToSerializableCertificate(
								args.CertSource,
								args.InputFile,
								args.NodeId)));
			}
			catch (Exception e)
			{
				si =
					new StatusInfo(
						new ErrorInfo(ErrorCodes.CertificateExtractionException, ErrorType.CertificateExtraction, e.Message));
			}

			return si;
		}

		private static StatusInfo VerifyAndExtract(ArgsInfo args)
		{
			StatusInfo si = Verify(args);
			if (!si.IsError)
			{
				if (si.Result.SignatureIsCorrect.HasValue && si.Result.SignatureIsCorrect.Value)
				{
					args.CertSource = CertificateProcessor.CertificateSource.Xml;
					si = Extract(args);
				}
			}
			return si;
		}
		#endregion

	}
}
