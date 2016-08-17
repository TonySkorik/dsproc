using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace dsproc.DataModel {
	[DataContract(Name = "status")]
	class StatusInfo: IJsonable {

		[DataMember(Name = "error")]
		public ErrorInfo Error { set; get; }
		[DataMember(Name = "is_error")]
		public bool IsError { get; }
		
		public string ToJsonString() {
			return JsonConvert.SerializeObject(this, Formatting.Indented);
		}
	}
}
