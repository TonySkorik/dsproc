using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace UniDsproc.DataModel {
	public class ErrorTypeEnumConverter : JsonConverter {
		public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) {
			ErrorType errorType = (ErrorType)value;
			writer.WriteValue(value.ToString());
		}
		

		public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer) {
			ErrorType ert;
			if (ErrorType.TryParse((string) reader.Value, true, out ert)) {
				return ert;
			} else {
				return null;
			}
		}

		public override bool CanConvert(Type objectType) {
			return objectType == typeof(ErrorType);
		}
	}

	public class PrintableInfo {
		private JsonSerializerSettings _settings = new JsonSerializerSettings() {
			DefaultValueHandling = DefaultValueHandling.Ignore,
			Formatting = Formatting.Indented,
			StringEscapeHandling = StringEscapeHandling.Default,
			

		};
		public virtual string ToJsonString() {
			return JsonConvert.SerializeObject(this,_settings);
		}
	}
}
