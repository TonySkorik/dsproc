using System;
using Newtonsoft.Json;

namespace UniDsproc.DataModel
{

	#region [JSON CONVERTERS]

	#region [ERRORTYPE -> ENUM]
	public class ErrorTypeEnumConverter : JsonConverter
	{
		public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
		{
			ErrorType errorType = (ErrorType)value;
			writer.WriteValue(errorType.ToString());
		}

		public override object ReadJson(
			JsonReader reader,
			Type objectType,
			object existingValue,
			JsonSerializer serializer)
		{
			if (Enum.TryParse((string)reader.Value, true, out ErrorType ert))
			{
				return ert;
			}
			else
			{
				return null;
			}
		}

		public override bool CanConvert(Type objectType)
		{
			return objectType == typeof(ErrorType);
		}
	}
	#endregion

	#region [BOOL -> INT]
	public class BoolToIntConverter : JsonConverter
	{
		public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
		{
			writer.WriteValue(
				(bool)value
					? "1"
					: "0");
		}


		public override object ReadJson(
			JsonReader reader,
			Type objectType,
			object existingValue,
			JsonSerializer serializer)
		{
			return (string)reader.Value == "1";
		}

		public override bool CanConvert(Type objectType)
		{
			return objectType == typeof(bool);
		}
	}
	#endregion

	#region [BOOL? -> INT]
	public class BoolToIntConverterNullable : JsonConverter
	{
		public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
		{
			if (((bool?)value).HasValue)
			{
				writer.WriteValue(
					((bool?)value).Value
						? "1"
						: "0");
			}
		}


		public override object ReadJson(
			JsonReader reader,
			Type objectType,
			object existingValue,
			JsonSerializer serializer)
		{
			return (string)reader.Value == "1";
		}

		public override bool CanConvert(Type objectType)
		{
			return objectType == typeof(bool?);
		}
	}
	#endregion

	#endregion

	public class PrintableInfo
	{
		private readonly JsonSerializerSettings _settings = new JsonSerializerSettings()
		{
			DefaultValueHandling = DefaultValueHandling.Ignore,
			Formatting = Formatting.Indented,
			StringEscapeHandling = StringEscapeHandling.Default,
		};

		public virtual string ToJsonString()
		{
			return JsonConvert.SerializeObject(this, _settings);
		}
	}
}
