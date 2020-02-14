using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Reflection;
using SmartBind;
using Space.Core;
using Space.Core.Configuration;
using Space.Core.Infrastructure;

namespace UniDsproc.DataModel
{
	public enum ProgramFunction
	{
		Sign = 1,
		Verify = 2,
		Extract = 3,
		VerifyAndExtract = 4
	}

	public class ArgsInfo
	{

		#region [AVAILABLE KEYS]

		private const string _signatureTypeKey = "signature_type";
		//private const string _smevModeKey = "smev_mode";
		//private const string _nodeIdKey = "node_id";
		//private const string _nodeNameKey = "node_name";
		//private const string _nodeNamespaceKey = "node_namespace";
		private const string _certificateThumbprintKey = "thumbprint";
		private const string _cerFilePathKey = "cer_file";
		private const string _certificateSourceKey = "certificate_source";

		private readonly Dictionary<string, PropertyInfo> _knownArgs = CommandLineBind.BuildBindings(typeof(ArgsInfo));

		#endregion

		#region [P & F]

		public readonly ProgramFunction Function;
		//=============================== via reflection set
		[ArgBinding("signature_type")]
		public SignatureType SigType { set; get; }
		[ArgBinding("gost_flavor")]
		public GostFlavor GostFlavor { set; get; } = GostFlavor.Gost_Obsolete;
		[ArgBinding("node_id")]
		public string NodeId { set; get; }
		[ArgBinding("thumbprint")]
		public string CertThumbprint { set; get; }
		[ArgBinding("cer_file")]
		public string CertFilePath { set; get; }
		[ArgBinding("ds")]
		public bool AssignDsInSignature { set; get; } // digital signature nodes will be put in XML namespace ds:
		[ArgBinding("ignore_expired")]
		public bool IgnoreExpiredCert { set; get; } //means there will be no expiration check before signing
		[ArgBinding(_certificateSourceKey)]
		public CertificateProcessor.CertificateSource CertSource { set; get; }
		//================================
		public CertificateLocation CertLocation;
		public string InputFile { get; }
		public string OutputFile { get; }
		public bool Ok { get; }
		public ErrorInfo InitError { get; }

		#endregion

		public ArgsInfo(string[] args, bool isBypassFileChecks)
		{
			Ok = false;

			SigType = SignatureType.Unknown;
			IgnoreExpiredCert = false;
			CertSource = CertificateProcessor.CertificateSource.Unknown;

			if (args.Length == 0)
			{
				InitError = new ErrorInfo(
					ErrorCodes.ArgumentNullValue,
					ErrorType.ArgumentParsing,
					"Command line is empty!");
				return;
			}

			string function = args[0];
			if (!Enum.TryParse(function, true, out Function))
			{
				InitError = new ErrorInfo(
					ErrorCodes.UnknownFunction,
					ErrorType.ArgumentParsing,
					$"Unknown program command - <{function}>");
				return;
			}

			#region [SWITCHES PARSING]
			Dictionary<string, string> switches = new Dictionary<string, string>();
			try
			{
				switches =
					args
						.Where(arg => arg.StartsWith("-"))
						.Select((arg) => arg.Split('='))
						.ToDictionary(
							(argvs) =>
							{
								string keyName = argvs[0].Substring(1);
								if (_knownArgs.ContainsKey(keyName))
								{
									return argvs[0].Substring(1);
								}

								throw new ArgumentOutOfRangeException(keyName, $"Unknown argument <{keyName}>");
							},
							(argvs) =>
							{
								string keyName = argvs[0].Substring(1);
								if (!string.IsNullOrEmpty(argvs[1]))
								{
									if (_knownArgs.ContainsKey(keyName))
									{
										if (_knownArgs[keyName].PropertyType.Name == typeof(bool).Name)
										{
											//bool
											_knownArgs[keyName].SetValue(
												this,
												argvs[1].ToLower() == "true" || argvs[1] == "1"
												|| argvs[1].ToLower() == "on");
										}
										else if (_knownArgs[keyName].PropertyType.Name == typeof(byte).Name)
										{
											//byte
											if (byte.TryParse(argvs[1], out byte smevNum))
											{
												if (smevNum == 2
													|| smevNum == 3)
												{
													_knownArgs[keyName].SetValue(this, smevNum);
												}
												else
												{
													throw new ArgumentNullException(
														keyName,
														$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values : <2> or <3>");
												}
											}
											else
											{
												throw new ArgumentNullException(
													keyName,
													$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values : <2> or <3>");
											}

										}
										else if (_knownArgs[keyName].PropertyType.Name == typeof(SignatureType).Name)
										{
											//SignatureType
											if (Enum.TryParse(
												argvs[1].Replace(".", "").Replace("_", ""),
												true,
												out SignatureType stype))
											{
												_knownArgs[keyName].SetValue(this, stype);
											}
											else
											{
												throw new ArgumentNullException(
													keyName,
													$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values are : <smev2_base.detached>, <smev2_charge.enveloped>, <smev2_sidebyside.detached>, <smev3_base.detached>, <smev3_sidebyside.detached>, <smev3_ack>, <sig.detached>");
											}
										}
										else if (_knownArgs[keyName].PropertyType.Name == typeof(GostFlavor).Name)
										{
											//GostFlavor
											if (Enum.TryParse(argvs[1], true, out GostFlavor gostFlavor))
											{
												_knownArgs[keyName].SetValue(this, gostFlavor);
											}
											else
											{
												_knownArgs[keyName].SetValue(this, GostFlavor.Gost_Obsolete);
												//throw new ArgumentNullException(keyName, $"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values are : <None>, <Gost_Obsolete>, <Gost2012_256>, <Gost2012_512>");
											}
										}
										else if (_knownArgs[keyName].PropertyType.Name
											== typeof(CertificateProcessor.CertificateSource).Name)
										{
											//CertificateSource
											if (Enum.TryParse(
												argvs[1].Replace(".", "").Replace("_", ""),
												true,
												out CertificateProcessor.CertificateSource csource))
											{
												_knownArgs[keyName].SetValue(this, csource);
											}
											else
											{
												throw new ArgumentNullException(
													keyName,
													$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values are : <xml> <base64> <cer>");
											}
										}
										else
										{
											//string
											if (keyName == _cerFilePathKey
												&& !File.Exists(argvs[1]))
											{
												throw new ArgumentNullException(
													keyName,
													$"Argument <{keyName}> value <{argvs[1]}> is invalid. File not found.");
											}

											_knownArgs[keyName].SetValue(this, argvs[1]);
										}
									}

									return argvs[1];
								}

								throw new ArgumentNullException(keyName, $"Argument <{keyName}> value is NULL");
							});
			}
			catch (ArgumentOutOfRangeException e)
			{
				InitError = new ErrorInfo(ErrorCodes.UnknownArgument, ErrorType.ArgumentParsing, e.Message);
				return;
			}
			catch (ArgumentNullException e)
			{
				InitError = new ErrorInfo(ErrorCodes.ArgumentInvalidValue, ErrorType.ArgumentParsing, e.Message);
				return;
			}
			catch (Exception e)
			{
				InitError = new ErrorInfo(
					ErrorCodes.UnknownException,
					ErrorType.ArgumentParsing,
					$"Unknown exception : {e.Message}");
				return;
			}
			#endregion

			//remove switches from comand line
			args = args.Where(arg => !arg.StartsWith("-")).ToArray();

			#region [FUNCTION BASED ARGS CHECK]
			
			switch (Function)
			{
				case ProgramFunction.Sign:

					#region [SIGN]

					if (string.IsNullOrEmpty(CertThumbprint))
					{
						InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							$"<{_certificateThumbprintKey}> value is empty! This value is required!");
						return;
					}

					if (SigType == SignatureType.Unknown)
					{
						InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							$"<{_signatureTypeKey}> value is empty! This value is required!");
						return;
					}

					if (isBypassFileChecks)
					{
						InputFile = null;
						OutputFile = null;
						Ok = true;
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
						InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							"Output file not specified!");
						return;
					}
					else if (args.Length == 1)
					{
						//means no files passed
						InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							"Neither input nor output file is specified!");
						return;
					}

					if (File.Exists(infile))
					{
						InputFile = infile;
						OutputFile = outfile;
						Ok = true;
					}
					else
					{
						InitError = new ErrorInfo(
							ErrorCodes.FileNotExist,
							ErrorType.ArgumentParsing,
							$"Input file <{infile}> not found");
					}
					

					break;
				#endregion

				case ProgramFunction.Extract:

					#region [EXTRACT]
					if (CertSource == CertificateProcessor.CertificateSource.Unknown)
					{
						InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							$"<{_certificateSourceKey}> value is empty! This value is required!");
						return;
					}

					string extractFile = args[args.Length - 1];
					if (File.Exists(extractFile))
					{
						InputFile = extractFile;
						Ok = true;
					}
					else
					{
						InitError = new ErrorInfo(
							ErrorCodes.FileNotExist,
							ErrorType.ArgumentParsing,
							$"Input file <{extractFile}> not found");
					}

					break;
				#endregion

				case ProgramFunction.Verify:
				case ProgramFunction.VerifyAndExtract:

					#region [VERIFY]
					if (SigType == SignatureType.Unknown)
					{
						InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							$"<{_signatureTypeKey}> value is empty! This value is required!");
						return;
					}

					string verfile = string.Empty;
					if (args.Length == 2)
					{
						verfile = args[args.Length - 1];
						if (File.Exists(verfile))
						{
							InputFile = verfile;
						}
						else
						{
							InitError = new ErrorInfo(
								ErrorCodes.FileNotExist,
								ErrorType.ArgumentParsing,
								$"Input file <{verfile}> not found");
							return;
						}
					}
					else if (args.Length < 2)
					{
						//means there is only one file passed - let it be input
						InitError = new ErrorInfo(
							ErrorCodes.ArgumentNullValue,
							ErrorType.ArgumentParsing,
							"Input file not specified!");
						return;
					}

					if (!string.IsNullOrEmpty(CertThumbprint))
					{
						//means there is a thumbprint
						CertLocation = CertificateLocation.Thumbprint;
					}
					else
					{
						//no thumbprint passed
						if (!string.IsNullOrEmpty(CertFilePath))
						{
							if (File.Exists(CertFilePath))
							{
								//means cer file exists
								CertLocation = CertificateLocation.CerFile;
							}
							else
							{
								//passed file doesn't exist
								InitError = new ErrorInfo(
									ErrorCodes.ArgumentInvalidValue,
									ErrorType.ArgumentParsing,
									$"Certificate file <{CertFilePath}> not found");
								return;
							}
						}
						else
						{
							//no thumbprint && cer file passed - check on X509Certificate node
							CertLocation = CertificateLocation.Xml;
						}
					}

					Ok = true;
					break;
				#endregion
			}
			#endregion
		}
	}
}
