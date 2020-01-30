using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Text;
using System.Threading.Tasks;

namespace Unismev.Api.Infrastructure
{
	public class PlainTextFormatter : MediaTypeFormatter
	{
		public override bool CanReadType(Type type)
		{
			throw new NotImplementedException();
		}

		public override bool CanWriteType(Type type)
		{
			throw new NotImplementedException();
		}

		public override Task<object> ReadFromStreamAsync(Type type, Stream readStream, HttpContent content, IFormatterLogger formatterLogger)
		{
			return base.ReadFromStreamAsync(type, readStream, content, formatterLogger);
		}

		public override Task WriteToStreamAsync(
			Type type,
			object value,
			Stream writeStream,
			HttpContent content,
			TransportContext transportContext)
		{
			return base.WriteToStreamAsync(type, value, writeStream, content, transportContext);
		}
	}
}
