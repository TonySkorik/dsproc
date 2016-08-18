using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace UniDsproc.DataModel {
	public enum ErrorType { ArgumentParsing, Signing };

	[DataContract(Name = "error")]
	public class ErrorInfo:IJsonable {

		[DataMember(Name = "error_code")]
		public string ErrorCode { get; }

		[DataMember(Name = "type")]
		public ErrorType Type { get; }

		[DataMember(Name = "message")]
		public string Message { get; }

		public ErrorInfo(string errorCode, ErrorType errorType, string msg) {
			ErrorCode = errorCode;
			Type = errorType;
			Message = msg.Split('\r')[0]; // because error message from exception contains unwanted string seperated by \r\n
		}

		public string ToJsonString() {
			return JsonConvert.SerializeObject(this,Formatting.Indented);
		}
	}
}
