using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace UniDsproc.DataModel {
	[DataContract(Name = "result")]
	public class ResultInfo:PrintableInfo {

		[DataMember(Name = "message")]
		public string Message { get; }

		public ResultInfo(string msg) {
			Message = msg;
		}
	}
}
