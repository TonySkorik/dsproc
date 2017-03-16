using System.Xml;
using System.Xml.Linq;

namespace Space.Core.Extensions {

	#region [XDOC <=> XMLDOC] extension methods
	public static class XdocConversionExtensions {
		public static XElement GetXElement(this XmlNode node) {
			XDocument xDoc = new XDocument();
			using(XmlWriter xmlWriter = xDoc.CreateWriter())
				node.WriteTo(xmlWriter);
			return xDoc.Root;
		}

		public static XmlNode GetXmlNode(this XElement element) {
			using(XmlReader xmlReader = element.CreateReader()) {
				XmlDocument xmlDoc = new XmlDocument();
				xmlDoc.Load(xmlReader);
				return xmlDoc;
			}
		}

		public static XDocument GetXDocument(this XmlDocument document) {
			XDocument xDoc = new XDocument();
			XmlWriterSettings settings = new XmlWriterSettings() {
				OmitXmlDeclaration = true,
				NewLineHandling = NewLineHandling.None
			};
			//using (XmlWriter xmlWriter = xDoc.CreateWriter()) {
			using(XmlWriter xmlWriter = XmlWriter.Create(xDoc.CreateWriter(), settings)) {
				document.WriteTo(xmlWriter);
			}
			/*
			XmlDeclaration decl =
			    document.ChildNodes.OfType<XmlDeclaration>().FirstOrDefault();
			if(decl != null)
				xDoc.Declaration = new XDeclaration(decl.Version, decl.Encoding,
				    decl.Standalone);
			*/
			return xDoc;
		}

		public static XmlDocument GetXmlDocument(this XDocument document) {
			using(XmlReader xmlReader = document.CreateReader()) {
				XmlDocument xmlDoc = new XmlDocument();
				xmlDoc.Load(xmlReader);
				if(document.Declaration != null) {
					XmlDeclaration dec = xmlDoc.CreateXmlDeclaration(document.Declaration.Version,
						document.Declaration.Encoding, document.Declaration.Standalone);
					xmlDoc.InsertBefore(dec, xmlDoc.FirstChild);
				}
				return xmlDoc;
			}
		}
	}
	#endregion

}
