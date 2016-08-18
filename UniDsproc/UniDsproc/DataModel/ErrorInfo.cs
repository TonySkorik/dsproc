using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace UniDsproc.DataModel {
	public enum ErrorType { ArgumentParsing, Signing };

	[DataContract(Name = "error")]
	public class ErrorInfo:PrintableInfo {

		[DataMember(Name = "error_code")]
		public string ErrorCode { get; }

		[DataMember(Name = "type")]
		[JsonConverter(typeof(ErrorTypeEnumConverter))]
		public ErrorType Type { get; }

		[DataMember(Name = "message")]
		public string Message { get; }

		public ErrorInfo(string errorCode, ErrorType errorType, string msg) {
			ErrorCode = errorCode;
			Type = errorType;
			string[] msgParts = (msg.Split('\r')[0]).Split(']'); // because error message from exception contains unwanted string seperated by \r\n
			if (msgParts.Length == 2) {
				ErrorCode = msgParts[0].Trim();
				Message = msgParts[1].Trim();
			} else {
				Message = msg.Split('\r')[0]; // because error message from exception contains unwanted string seperated by \r\n
			}
			
		}
	}
}
