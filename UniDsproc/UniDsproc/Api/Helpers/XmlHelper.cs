using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace UniDsproc.Api.Helpers
{
	internal static class XmlHelper
	{
		public static XDocument TryParseAsXdocument(this string xmlData)
		{
			XDocument ret = null;

			try
			{
				ret = XDocument.Parse(xmlData);
			}
			catch
			{
				// ignore parsing error
			}

			return ret;
		}
	}
}
