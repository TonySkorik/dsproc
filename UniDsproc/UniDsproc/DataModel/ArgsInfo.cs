using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Space.Core.Configuration;
using Space.Core.Infrastructure;
using Space.Core.Processor;
using UniDsproc.Infrastructure;

namespace UniDsproc.DataModel
{
	public enum ProgramFunction
	{
		Sign = 1,
		Verify = 2,
		Extract = 3,
		VerifyAndExtract = 4,
		Describe = 5
	}

	public class ArgsInfo
	{
		#region Private

		private const string _signatureTypeKey = "signature_type";
		private const string _certificateThumbprintKey = "thumbprint";
		private const string _certificateNickKey = "cert_nick";
		private const string _cerFilePathKey = "cer_file";
		private const string _certificateSourceKey = "certificate_source";
		private const string _isVerifyCertificateChainKey = "is_check_cert_chain";

		private static readonly Dictionary<string, PropertyInfo> _knownArgs = CommandLineBind.BuildBindings(typeof(ArgsInfo));

		#endregion

		#region Props
		
		#region Set via reflection

		[ArgBinding(_signatureTypeKey)]
		public SignatureType SigType { set; get; }

		[ArgBinding("gost_flavor")]
		public GostFlavor GostFlavor { set; get; } = GostFlavor.Gost_Obsolete;

		[ArgBinding("node_id")]
		public string NodeId { set; get; }

		[ArgBinding(_certificateThumbprintKey)]
		public string CertificateThumbprint { set; get; }

		[ArgBinding(_certificateNickKey)]
		public string CertificateNick { set; get; }

		[ArgBinding(_cerFilePathKey)]
		public string CertificateFilePath { set; get; }

		[ArgBinding("ds")]
		public bool AssignDsInSignature { set; get; } // digital signature nodes will be put in XML namespace ds:

		[ArgBinding("ignore_expired")]
		public bool IgnoreExpiredCertificate { set; get; } //means there will be no expiration check before signing

		[ArgBinding("add_signing_time")]
		public bool IsAddSigningTime { set; get; }

		[ArgBinding(_certificateSourceKey)]
		public CertificateSource CertificateSource { set; get; }

		[ArgBinding(_isVerifyCertificateChainKey)]
		public bool IsVerifyCertificateChain { set; get; }

		#endregion

		public ProgramFunction Function { get; private set; }
		public CertificateLocation CertificateLocation { private set; get; }
		public string InputFile { get; private set; }
		public string OutputFile { get; private set; }
		public bool Ok { get; private set; }
		public ErrorInfo InitError { get; private set; }

		#endregion

		#region Ctor

		/// <summary>
		/// Prevents a default instance of the <see cref="ArgsInfo"/> class from being created.
		/// </summary>
		private ArgsInfo()
		{
			Ok = false;

			SigType = SignatureType.Unknown;
			IgnoreExpiredCertificate = false;
			IsAddSigningTime = false;
			CertificateSource = CertificateSource.Unknown;
		}
		
		#endregion

		#region Methods for arguments parsing

		public static ArgsInfo Parse(string[] args, bool isBypassFileChecks, Dictionary<string, string> knownCertificateThumbprints)
		{
			var ret = new ArgsInfo();

			if (args.Length == 0)
			{
				ret.InitError = new ErrorInfo(
					ErrorCodes.ArgumentNullValue,
					ErrorType.ArgumentParsing,
					"Command line is empty!");
				return ret;
			}

			string function = args[0];
			if (!Enum.TryParse(function, true, out ProgramFunction parsedFunction))
			{
				ret.InitError = new ErrorInfo(
					ErrorCodes.UnknownFunction,
					ErrorType.ArgumentParsing,
					$"Unknown program command - <{function}>");
				return ret;
			}

			ret.Function = parsedFunction;

			try
			{
				ParseKnownSwitches(ret, args);
				args = args.Where(arg => !arg.StartsWith("-")).ToArray();
			}
			catch (Exception e)
			{
				ret.InitError = new ErrorInfo(
					ErrorCodes.UnknownException,
					ErrorType.ArgumentParsing,
					$"Unknown exception happened during command line switches parse: {e.Message}");
				return ret;
			}

			// set certificate thumbprint from certificate thumbprint nick
			if (string.IsNullOrEmpty(ret.CertificateThumbprint)
				&& !string.IsNullOrEmpty(ret.CertificateNick)
				&& knownCertificateThumbprints.ContainsKey(ret.CertificateNick.ToLowerInvariant()))
			{
				ret.CertificateThumbprint = knownCertificateThumbprints[ret.CertificateNick.ToLowerInvariant()];
			}

			CheckArgumentsAndSetFiles(ret, args, isBypassFileChecks);

			return ret;
		}

		private static void ParseKnownSwitches(ArgsInfo target, string[] args)
		{
			foreach (var argvs in args.Where(arg => arg.StartsWith("-")).Select((arg) => arg.Split('=')))
			{
				string keyName = argvs[0].Substring(1);
				if (!_knownArgs.ContainsKey(keyName))
				{
					target.InitError = new ErrorInfo(ErrorCodes.UnknownArgument, ErrorType.ArgumentParsing, $"Unknown argument <{keyName}>");
					return;
				}

				if (string.IsNullOrEmpty(argvs[1]))
				{
					target.InitError = new ErrorInfo(ErrorCodes.ArgumentInvalidValue, ErrorType.ArgumentParsing, $"Argument <{keyName}> value is NULL");
					return;
				}

				if (_knownArgs[keyName].PropertyType.Name == nameof(Boolean))
				{
					//parse bool
					_knownArgs[keyName].SetValue(
						target,
						argvs[1].ToLower() == "true" || argvs[1] == "1"
						|| argvs[1].ToLower() == "on");
				}
				else if (_knownArgs[keyName].PropertyType.Name == nameof(Byte))
				{
					//parse byte
					if (byte.TryParse(argvs[1], out byte smevNum))
					{
						if (smevNum == 2
							|| smevNum == 3)
						{
							_knownArgs[keyName].SetValue(target, smevNum);
						}
						else
						{
							target.InitError = new ErrorInfo(
								ErrorCodes.ArgumentInvalidValue,
								ErrorType.ArgumentParsing,
								$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values : <2> or <3>");
							return;
						}
					}
					else
					{
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentInvalidValue,
							ErrorType.ArgumentParsing,
							$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values : <2> or <3>");
						return;
					}

				}
				else if (_knownArgs[keyName].PropertyType.Name == nameof(SignatureType))
				{
					//parse SignatureType
					if (Enum.TryParse(
						argvs[1].Replace(".", "").Replace("_", ""),
						true,
						out SignatureType stype))
					{
						_knownArgs[keyName].SetValue(target, stype);
					}
					else
					{
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentInvalidValue,
							ErrorType.ArgumentParsing,
							$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values are : <smev2_base.detached>, <smev2_charge.enveloped>, <smev2_sidebyside.detached>, <smev3_base.detached>, <smev3_sidebyside.detached>, <smev3_ack>, <sig.detached>");
						return;
					}
				}
				else if (_knownArgs[keyName].PropertyType.Name == nameof(Space.Core.Infrastructure.GostFlavor))
				{
					//parse GostFlavor
					_knownArgs[keyName].SetValue(
						target,
						Enum.TryParse(argvs[1], true, out GostFlavor gostFlavor)
							? gostFlavor
							: GostFlavor.Gost_Obsolete);
				}
				else if (_knownArgs[keyName].PropertyType.Name == nameof(CertificateSource))
				{
					//parse CertificateSource
					if (Enum.TryParse(
						argvs[1].Replace(".", "").Replace("_", ""),
						true,
						out CertificateSource csource))
					{
						_knownArgs[keyName].SetValue(target, csource);
					}
					else
					{
						target.InitError = new ErrorInfo(ErrorCodes.ArgumentInvalidValue, ErrorType.ArgumentParsing, $"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values are : <xml> <base64> <cer>");
						return;
					}
				}
				else
				{
					//parse string
					if (keyName == _cerFilePathKey
						&& !File.Exists(argvs[1]))
					{
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentInvalidValue,
							ErrorType.ArgumentParsing,
							$"Argument <{keyName}> value <{argvs[1]}> is invalid. File not found.");
						return;
					}

					_knownArgs[keyName].SetValue(target, argvs[1]);
				}
			}
		}

		private static void CheckArgumentsAndSetFiles(ArgsInfo target, string[] args, bool isBypassFileChecks)
		{
			switch (target.Function)
			{
				case ProgramFunction.Sign:
					if (string.IsNullOrEmpty(target.CertificateThumbprint) && string.IsNullOrEmpty(target.CertificateNick))
					{
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							$"Both <{_certificateThumbprintKey}> and <{_certificateNickKey}> values are empty! One of these values is required!");
						return;
					}

					if (target.SigType == SignatureType.Unknown)
					{
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							$"<{_signatureTypeKey}> value is empty! This value is required!");
						return;
					}

					if (isBypassFileChecks)
					{
						target.InputFile = null;
						target.OutputFile = null;
						target.Ok = true;
						break;
					}

					string infile = string.Empty;
					string outfile = string.Empty;

					if (args.Length == 3)
					{
						infile = args[args.Length - 2];
						outfile = args[args.Length - 1];
					}
					else if (args.Length == 2)
					{
						//means there is only one file passed - let it be input
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							"Output file not specified!");
						return;
					}
					else if (args.Length == 1)
					{
						//means no files passed
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							"Neither input nor output file is specified!");
						return;
					}

					if (File.Exists(infile))
					{
						target.InputFile = infile;
						target.OutputFile = outfile;
						target.Ok = true;
					}
					else
					{
						target.InitError = new ErrorInfo(
							ErrorCodes.FileNotExist,
							ErrorType.ArgumentParsing,
							$"Input file <{infile}> not found");
					}

					break;
				case ProgramFunction.Extract:
					if (target.CertificateSource == CertificateSource.Unknown)
					{
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							$"<{_certificateSourceKey}> value is empty! This value is required!");
						return;
					}

					string extractFile = args[args.Length - 1];
					if (File.Exists(extractFile))
					{
						target.InputFile = extractFile;
						target.Ok = true;
					}
					else
					{
						target.InitError = new ErrorInfo(
							ErrorCodes.FileNotExist,
							ErrorType.ArgumentParsing,
							$"Input file <{extractFile}> not found");
					}

					break;
				case ProgramFunction.Verify:
				case ProgramFunction.VerifyAndExtract:
					if (target.SigType == SignatureType.Unknown)
					{
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							$"<{_signatureTypeKey}> value is empty! This value is required!");
						return;
					}

					if (args.Length == 2)
					{
						string verfile = args[args.Length - 1];
						if (File.Exists(verfile))
						{
							target.InputFile = verfile;
						}
						else
						{
							target.InitError = new ErrorInfo(
								ErrorCodes.FileNotExist,
								ErrorType.ArgumentParsing,
								$"Input file <{verfile}> not found");
							return;
						}
					}
					else if (args.Length < 2)
					{
						//means there is only one file passed - let it be input
						target.InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							"Input file not specified!");
						return;
					}

					if (!string.IsNullOrEmpty(target.CertificateThumbprint))
					{
						//means there is a thumbprint
						target.CertificateLocation = CertificateLocation.Thumbprint;
					}
					else
					{
						//no thumbprint passed
						if (!string.IsNullOrEmpty(target.CertificateFilePath))
						{
							if (File.Exists(target.CertificateFilePath))
							{
								//means cer file exists
								target.CertificateLocation = CertificateLocation.CerFile;
							}
							else
							{
								//passed file doesn't exist
								target.InitError = new ErrorInfo(
									ErrorCodes.ArgumentInvalidValue,
									ErrorType.ArgumentParsing,
									$"Certificate file <{target.CertificateFilePath}> not found");
								return;
							}
						}
						else
						{
							//no thumbprint && cer file passed - check on X509Certificate node
							target.CertificateLocation = CertificateLocation.Xml;
						}
					}

					target.Ok = true;
					break;
				default:
					throw new ArgumentOutOfRangeException(nameof(target.Function), target.Function, "Unknown program function");
			}
		}

		#endregion

		#region ToString implementation
		
		public override string ToString()
		{
			var ret = $"{nameof(SignatureType)}={SigType};{nameof(GostFlavor)}={GostFlavor};{nameof(CertificateThumbprint)}={CertificateThumbprint};{nameof(NodeId)}={NodeId}";
			if (!string.IsNullOrEmpty(CertificateNick))
			{
				ret = $"{ret};{nameof(CertificateNick)}={CertificateNick}";
			}

			return ret;
		} 

		#endregion
	}
}
