using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Serilog;
using Space.Core;
using Space.Core.Configuration;
using Space.Core.Interfaces;
using Space.Core.Processor;
using Space.Core.Serializer;
using Space.Core.Verifier;
using Topshelf;
using UniDsproc.Api;
using UniDsproc.Configuration;
using UniDsproc.DataModel;

namespace UniDsproc
{
	internal class Program
	{
		public static string Version { get; } =
		$"{Assembly.GetExecutingAssembly().GetName().Version.Major}"
			+ $".{Assembly.GetExecutingAssembly().GetName().Version.Minor}"
			+ $".{Assembly.GetExecutingAssembly().GetName().Version.Build}"
			+ $".{Assembly.GetExecutingAssembly().GetName().Version.Revision}";

		private static string GetVersionName => "Verbose";

		public static WebApiHost WebApiHost { get; private set; }

		private static void Main(string[] args)
		{
			if (args.Length <= 0)
			{
				ShowHelp();
				return;
			}
			
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

			ArgsInfo inputArguments = ArgsInfo.Parse(args, false, configuration.Signer.KnownThumbprints);
			var statusInfo = MainCore(inputArguments);
			Console.WriteLine(statusInfo.ToJsonString());
		}

		#region Initialization methods

		private static void InitializeLogger(AppSettings settings)
		{
			var loggerConfig = new LoggerConfiguration()
				.WriteTo
				.File(settings.Logger.FilePath)
				.WriteTo
				.Console(outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
				.MinimumLevel
				.Is(settings.Logger.MinimumEventLevel);

			Log.Logger = loggerConfig.CreateLogger();
		}

		public static AppSettings GetConfiguration()
		{
			var configRoot = new ConfigurationBuilder().AddJsonFile("UniDsproc.json").Build();
			AppSettings ret = configRoot.Get<AppSettings>();

			// normalize Thumbprints settings
			if(ret.Signer.KnownThumbprints != null && ret.Signer.KnownThumbprints.Count > 0)
			{
				ret.Signer.KnownThumbprints = ret.Signer.KnownThumbprints.ToDictionary(
					kv => kv.Key.ToLowerInvariant(), // lower the keys
					kv => kv.Value.Replace(" ", "") // remove extra spaces
				); 
			}

			return ret;
		}

		#endregion

		#region Web Api Service configuration methods

		private static void ConfigureService(string verb)
		{
			try
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
			catch (Exception ex)
			{
				Log.Logger.Error("Exception happened during service startup. {ex}", ex);
			}
		}

		#endregion
		
		#region Display help methods

		private static void ShowHelp()
		{
			string version = $"{Version} {GetVersionName}";
			var separator = $"{new string('-', 32)}\n";
			string ntt = "\n\t\t    ";
			string helpMessage = $"[UniDSProc v{version}]\n" +
				separator +
				$" Call string: UniDsproc.exe <function> [parameters] <input file> [output file]\n" +
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
				$" PARAMETERS: \n" +
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
				$"<Gost2012_512>\n" +
				$"		Default value : 'Gost_Obsolete'\n" +
				$"\n" +
				$"  node_id\n" +
				$"		String value of <Id> attribute of the node to be signed\n" +
				$"		Default value : 'ID_SIGN'\n\n" +
				$"  thumbprint [*:sign]\n" +
				$"		Signature certificate thumbprint\n\n" +
				$"  cert_nick [*:sign]\n" +
				$"		Signature certificate nick\n\n" +
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
				$"  add_signing_time [EXPERIMAENTAL]\n" +
				$"		Add signing time to a signed message attrinutes\n" +
				$"		Works only for Pkcs#7 signatures\n" +
				$"		Possible values : 'true', 'false', '1', '0', 'on', 'off'\n" +
				$"		Default value : 'false' \n\n" +
				$"  certificate_source [*:verify, verifyAndExtract]\n" +
				$"		Sets the source from which to extract the certificate\n" +
				$"		Possible values : 'xml', 'base64', 'cer'\n\n" +
				separator +
				$" WEB API: \n" +
				$"  UniDsProc supoorts two WEB API modes:\n" + 
				$"   - interactive api mode [function: api]\n" +
				$"\tIn this mode api server is hosted in currently running process.\n" +
				$"   - hosted service api mode [function: install]\n" +
				$"\tIn this mode UniDsProc intalls api server as a self-starting Windows service.\n" +
				$"  All API configuration is located in program settings file.\n\n" +
				separator +
				$" WEB API QUERIES: \n" +
				$"  All api queries (only POST verb is supported) are constructed as follows :\n\n" + 
				$"    http://<address>:<port>/api/v1/<function>/[?<parameter_name1>=<parameter_value1>][&<parameter_name2>=<parameter_value2>]\n\n" +
				$"  Only sign function is supported.\n" +
				$"  All parameters have the same names and values as in non-api mode.\n" +
				$"  Input file is passed via data_file POST body field.\n" +
				$"  Output file is passed back to a caller in response body as binary stream.\n" +
				$"  IMPORTANT!: when operating in API or service mode all parameters (except data_file) should be pased to a service via query string.\n" +
				$"";

			Console.WriteLine(helpMessage);
		}

		#endregion

		#region Program functions methods

		public static StatusInfo MainCore(ArgsInfo arguments)
		{
			if (arguments.Ok)
			{
				switch (arguments.Function)
				{
					case ProgramFunction.Sign:
						return Sign(arguments);
					case ProgramFunction.Verify:
						return Verify(arguments);
					case ProgramFunction.Extract:
						return Extract(arguments);
					case ProgramFunction.VerifyAndExtract:
						return VerifyAndExtract(arguments);
				}
			}
			return new StatusInfo(arguments.InitError);
		}

		private static StatusInfo Sign(ArgsInfo arguments)
		{
			ISigner signer = new Signer();
			try
			{
				string signedData = signer.Sign(
					arguments.SigType,
					arguments.GostFlavor,
					arguments.CertificateThumbprint,
					arguments.InputFile,
					arguments.AssignDsInSignature,
					arguments.NodeId,
					arguments.IgnoreExpiredCertificate,
					arguments.IsAddSigningTime);
				File.WriteAllText(arguments.OutputFile, signedData);
				return new StatusInfo($"OK. Signed file path: {arguments.OutputFile}");
			}
			catch (Exception e)
			{
				return new StatusInfo(new ErrorInfo(ErrorCodes.SigningFailed, ErrorType.Signing, $"{e.Message}"));
			}
		}

		private static StatusInfo Verify(ArgsInfo arguments)
		{
			try
			{
				ISignatureVerifier verifier = new SignatureVerifier();
				var verifierResult = verifier.VerifySignature(
					arguments.SigType,
					arguments.InputFile,
					arguments.CertificateLocation == CertificateLocation.CerFile
						? arguments.CertificateFilePath
						: null,
					arguments.CertificateLocation == CertificateLocation.Thumbprint
						? arguments.CertificateThumbprint
						: null,
					arguments.NodeId,
					isVerifyCertificateChain: arguments.IsVerifyCertificateChain
				);
				return verifierResult.IsSignatureMathematicallyValid && verifierResult.IsSignatureSigningDateValid
					? new StatusInfo(new ResultInfo("Signature is correct", true))
					: new StatusInfo(new ResultInfo("Signature is invalid", false));
			}
			catch (Exception e)
			{
				return new StatusInfo(new ErrorInfo(ErrorCodes.VerificationFailed, ErrorType.SignatureVerification, e.Message));
			}
		}

		private static StatusInfo Extract(ArgsInfo arguments)
		{
			StatusInfo si;
			try
			{
				ICertificateSerializer serializer = new CertificateSerializer();
				si =
					new StatusInfo(
						new ResultInfo(
							serializer.CertificateToSerializable(
								arguments.CertificateSource,
								arguments.InputFile,
								arguments.NodeId)));
			}
			catch (Exception e)
			{
				si =
					new StatusInfo(
						new ErrorInfo(ErrorCodes.CertificateExtractionException, ErrorType.CertificateExtraction, e.Message));
			}

			return si;
		}

		private static StatusInfo VerifyAndExtract(ArgsInfo arguments)
		{
			StatusInfo si = Verify(arguments);
			if (!si.IsError)
			{
				if (si.Result.SignatureIsCorrect.HasValue && si.Result.SignatureIsCorrect.Value)
				{
					arguments.CertificateSource = CertificateSource.Xml;
					si = Extract(arguments);
				}
			}
			return si;
		}

		#endregion
	}
}
