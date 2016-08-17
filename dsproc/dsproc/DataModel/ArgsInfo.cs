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

namespace dsproc.DataModel {
	public enum ProgramFunction {Sign = 1, Verify = 2, Extract = 3, VerifyAndExtract = 4}

	public class ArgsInfo {

		#region [AVAILABLE KEYS]
		private const string _signatureTypeKey = "signature_type";
		private const string _smevModeKey = "smev_mode";
		private const string _nodeIdKey = "node_id";
		private const string _nodeNameKey = "node_name";
		private const string _nodeNamespaceKey = "node_namespace";
		private const string _thumbprintKey = "thumbprint";
		private const string _verboseKey = "verbose";

		private Dictionary<string,PropertyInfo> _knownKeys = new Dictionary<string,PropertyInfo>{
			{_signatureTypeKey,typeof(ArgsInfo).GetProperty("SigType")},
			{_smevModeKey,typeof(ArgsInfo).GetProperty("SmevMode")},
			{_nodeIdKey,typeof(ArgsInfo).GetProperty("NodeId")},
			{_nodeNameKey,typeof(ArgsInfo).GetProperty("NodeName")},
			{_nodeNamespaceKey,typeof(ArgsInfo).GetProperty("NodeNamespace")},
			{_thumbprintKey,typeof(ArgsInfo).GetProperty("CertThumbprint")},
			{_verboseKey,typeof(ArgsInfo).GetProperty("IsDebugModeOn")}
		};
		#endregion

		#region [P & F]
		public readonly ProgramFunction Function;
		//=============================== via reflection set
		public SignatureType SigType { set; get; }
		public byte SmevMode { set; get; }
		public string NodeId { set; get; }
		public string NodeName { set; get; }
		public string NodeNamespace { set; get; }
		public string CertThumbprint { set; get; }
		public bool IsDebugModeOn { set; get; }
		//================================
		public SigningMode SigMode { set; get; }
		public string InputFile { get; }
		public string OutputFile { get; }
		public bool Ok { get; }
		
		public ErrorInfo InitError { get; }

		#endregion

		public ArgsInfo(string[] args) {
			Ok = false;
			string function = args[0];
			if(!ProgramFunction.TryParse(function, true, out Function)) {
				Ok = false;
				InitError = new ErrorInfo(ErrorCodes.UnknownFunction, ErrorType.ArgumentParsing, $"Unknown program command - <{function}>");
			}

			Dictionary<string, string> switches = new Dictionary<string, string>();
			try {
				switches =
					args
					.Where(arg => arg.StartsWith("-"))
					.Select((arg) => arg.Split('='))
					.ToDictionary((argvs) => {
						string keyName = argvs[0].Substring(1);
						if(_knownKeys.ContainsKey(keyName)) {
							return argvs[0].Substring(1);
						}
						throw new ArgumentOutOfRangeException($"Unknown argument <{keyName}>");
					}, (argvs) => {
						string keyName = argvs[0].Substring(1);
						if(!string.IsNullOrEmpty(argvs[1])) {
							if (_knownKeys.ContainsKey(keyName)) {
								if (_knownKeys[keyName].PropertyType.Name == typeof(bool).Name) {
									//bool
									_knownKeys[keyName].SetValue(this, argvs[1]=="true" || argvs[1] == "1");
								} else if (_knownKeys[keyName].PropertyType.Name == typeof(byte).Name) {
									//byte
									byte smevNum;
									if (byte.TryParse(argvs[1], out smevNum)) {
										if (smevNum == 2 || smevNum == 3) {
											_knownKeys[keyName].SetValue(this, smevNum);
										} else {
											throw new ArgumentNullException(keyName,$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values : <2> or <3>");
										}
									} else {
										throw new ArgumentNullException(keyName,$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values : <2> or <3>");
									}

								} else if(_knownKeys[keyName].PropertyType.Name == typeof(SignatureType).Name) {
									//SignatureType
									SignatureType stype;
									if (SignatureType.TryParse(argvs[1], true, out stype)) {
										_knownKeys[keyName].SetValue(this, stype);
									} else {
										throw new ArgumentNullException(keyName,$"Argument <{keyName}> value <{argvs[1]}> is invalid. Possible values are : <enveloped>, <sidebyside>, <detached>");
									}
								} else {
									_knownKeys[keyName].SetValue(this, argvs[1]);
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

			switch(Function) {
				case ProgramFunction.Sign:
					string infile = args[args.Length - 2];
					string outfile = args[args.Length - 1];

					if(File.Exists(infile)) {
						InputFile = infile;
						OutputFile = outfile;
						Ok = true;
					} else {
						InitError = new ErrorInfo(ErrorCodes.FileNotExist,ErrorType.ArgumentParsing,$"Input file <{infile}> doesn't exist");
					}

					break;
				case ProgramFunction.Extract:
					throw new NotImplementedException();
				case ProgramFunction.Verify:
					throw new NotImplementedException();
				case ProgramFunction.VerifyAndExtract:
					throw new NotImplementedException();
			}
		}
	}
}
