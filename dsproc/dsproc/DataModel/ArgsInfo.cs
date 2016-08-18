using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

using dsproc.SignatureProcessor;
using SmartBind;

namespace dsproc.DataModel {
	public enum ProgramFunction {Sign = 1, Verify = 2, Extract = 3, VerifyAndExtract = 4}

	public class ArgsInfo {

		#region [AVAILABLE KEYS]
		private const string _signatureTypeKey = "signature_type";
		private const string _smevModeKey = "smev_mode";
		private const string _nodeIdKey = "node_id";
		private const string _nodeNameKey = "node_name";
		private const string _nodeNamespaceKey = "node_namespace";
		private const string _certificateThumbprintKey = "thumbprint";
		private const string _cerFilePathKey = "cer_file";
		private const string _setDsKey = "ds";

		/*private Dictionary<string,PropertyInfo> _knownArgs = new Dictionary<string,PropertyInfo>{
			{_signatureTypeKey,typeof(ArgsInfo).GetProperty("SigType")},
			{_smevModeKey,typeof(ArgsInfo).GetProperty("SmevMode")},
			{_nodeIdKey,typeof(ArgsInfo).GetProperty("NodeId")},
			{_nodeNameKey,typeof(ArgsInfo).GetProperty("NodeName")},
			{_nodeNamespaceKey,typeof(ArgsInfo).GetProperty("NodeNamespace")},
			{_certificateThumbprintKey,typeof(ArgsInfo).GetProperty("CertThumbprint")},
			{_cerFilePathKey,typeof(ArgsInfo).GetProperty("CertFilePath")},
			//{_verboseKey,typeof(ArgsInfo).GetProperty("IsDebugModeOn")},
			{_setDsKey,typeof(ArgsInfo).GetProperty("AssignDsInSignature")}
		};*/

		private readonly Dictionary<string, PropertyInfo> _knownArgs = SmartBind.CommandLineBind.BuildBindings(typeof(ArgsInfo));

		#endregion

		#region [P & F]
		public readonly ProgramFunction Function;
		//=============================== via reflection set
		[ArgBinding("signature_type")]
		public SignatureType SigType { set; get; }
		[ArgBinding("smev_mode")]
		public byte SmevMode { set; get; }
		[ArgBinding("node_id")]
		public string NodeId { set; get; }
		[ArgBinding("node_name")]
		public string NodeName { set; get; }
		[ArgBinding("node_namespace")]
		public string NodeNamespace { set; get; }
		[ArgBinding("thumbprint")]
		public string CertThumbprint { set; get; }
		[ArgBinding("cer_file")]
		public string CertFilePath { set; get; }
		//public bool IsDebugModeOn { set; get; }
		[ArgBinding("ds")]
		public bool AssignDsInSignature { set; get; }
		//================================
		public SigningMode SigMode { set; get; }
		public string InputFile { get; }
		public string OutputFile { get; }
		public bool Ok { get; }
		
		public ErrorInfo InitError { get; }

		#endregion

		public ArgsInfo(string[] args) {
			Ok = false;

			SigType = SignatureType.Unknown;
			SmevMode = 0;

			string function = args[0];
			if(!ProgramFunction.TryParse(function, true, out Function)) {
				Ok = false;
				InitError = new ErrorInfo(ErrorCodes.UnknownFunction, ErrorType.ArgumentParsing, $"Unknown program command - <{function}>");
			}

			#region [SWITCHES PARSING]
			Dictionary<string, string> switches = new Dictionary<string, string>();
			try {
				switches =
					args
					.Where(arg => arg.StartsWith("-"))
					.Select((arg) => arg.Split('='))
					.ToDictionary((argvs) => {
						string keyName = argvs[0].Substring(1);
						if(_knownArgs.ContainsKey(keyName)) {
							return argvs[0].Substring(1);
						}
						throw new ArgumentOutOfRangeException($"Unknown argument <{keyName}>");
					}, (argvs) => {
						string keyName = argvs[0].Substring(1);
						if(!string.IsNullOrEmpty(argvs[1])) {
							if (_knownArgs.ContainsKey(keyName)) {
								if (_knownArgs[keyName].PropertyType.Name == typeof(bool).Name) {
									//bool
									_knownArgs[keyName].SetValue(this, argvs[1].ToLower() == "true" || argvs[1] == "1" || argvs[1].ToLower() == "on");
								} else if (_knownArgs[keyName].PropertyType.Name == typeof(byte).Name) {
									//byte
									byte smevNum;
									if (byte.TryParse(argvs[1], out smevNum)) {
										if (smevNum == 2 || smevNum == 3) {
											_knownArgs[keyName].SetValue(this, smevNum);
										} else {
											throw new ArgumentNullException(keyName,$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values : <2> or <3>");
										}
									} else {
										throw new ArgumentNullException(keyName,$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values : <2> or <3>");
									}

								} else if(_knownArgs[keyName].PropertyType.Name == typeof(SignatureType).Name) {
									//SignatureType
									SignatureType stype;
									if (SignatureType.TryParse(argvs[1], true, out stype)) {
										_knownArgs[keyName].SetValue(this, stype);
									} else {
										throw new ArgumentNullException(keyName,$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values are : <enveloped>, <sidebyside>, <detached>");
									}
								} else {
									//string
									if (keyName == _cerFilePathKey && !File.Exists(argvs[1])) {
										throw new ArgumentNullException(keyName, $"Argument <{keyName}> value <{argvs[1]}> is invalid. File not found.");
									}
									_knownArgs[keyName].SetValue(this, argvs[1]);
								}
							}
							return argvs[1];
						}
						throw new ArgumentNullException(keyName,$"Argument <{keyName}> value is NULL");
					});
			} catch(ArgumentOutOfRangeException e) {
				InitError = new ErrorInfo(ErrorCodes.UnknownArgument, ErrorType.ArgumentParsing, e.Message);
				return;
			} catch(ArgumentNullException e) {
				InitError = new ErrorInfo(ErrorCodes.ArgumentInvalidValue, ErrorType.ArgumentParsing, e.Message);
				return;
			} catch(Exception e) {
				InitError = new ErrorInfo(ErrorCodes.UnknownException, ErrorType.ArgumentParsing, $"Unknown exception : {e.Message}");
				return;
			}
			#endregion

			#region [FUNCTION BASED ARGS CHECK]

			switch(Function) {
				case ProgramFunction.Sign:
					//check args
					if (string.IsNullOrEmpty(CertThumbprint)) {
						InitError = new ErrorInfo(ErrorCodes.ArgumentNullValue, ErrorType.ArgumentParsing, $"<{_certificateThumbprintKey}> value is empty! This value is required!");
						return;
					}

					if (SigType == SignatureType.Unknown) {
						InitError = new ErrorInfo(ErrorCodes.ArgumentNullValue, ErrorType.ArgumentParsing, $"<{_signatureTypeKey}> value is empty! This value is required!");
						return;
					}

					switch (SigType) {
						case SignatureType.Detached:
							SigMode = SigningMode.Detached;
							break;
						case SignatureType.Enveloped:
							SigMode = SmevMode == 2 ? SigningMode.Smev2 : SigningMode.SimpleEnveloped;
							break;
						case SignatureType.SideBySide:
							SigMode = SmevMode != 3 ? SigningMode.Simple : SigningMode.Smev3; 
							break;
					}

					string infile = args[args.Length - 2];
					string outfile = args[args.Length - 1];

					if(File.Exists(infile)) {
						InputFile = infile;
						OutputFile = outfile;
						Ok = true;
					} else {
						InitError = new ErrorInfo(ErrorCodes.FileNotExist,ErrorType.ArgumentParsing,$"Input file <{infile}> not found");
					}

					break;
				case ProgramFunction.Extract:
					//check args
					string extractFile = args[args.Length - 1];
					if (File.Exists(extractFile)) {
						InputFile = extractFile;
						Ok = true;
					}else {
						InitError = new ErrorInfo(ErrorCodes.FileNotExist, ErrorType.ArgumentParsing, $"Input file <{extractFile}> not found");
					}
					break;
				case ProgramFunction.Verify:
					throw new NotImplementedException();
				case ProgramFunction.VerifyAndExtract:
					throw new NotImplementedException();
			}
			#endregion
		}
	}
}
