using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using CryptoPro.Sharpei.Xml;

namespace Space.Core
{
	/// <summary>
	/// Simple enveloped sign
	/// </summary>
	/// <seealso cref="Space.Core.Interfaces.ISigner" />
	public partial class Signer
	{
		private XmlDocument SignXmlFileEnveloped(XmlDocument doc, X509Certificate2 certificate, string nodeId = null)
		{
			//----------------------------------------------------------------------------------------------CREATE SIGNED XML
			SignedXml signedXml = new SignedXml(doc)
			{
				SigningKey = certificate.PrivateKey
			};
			//----------------------------------------------------------------------------------------------REFERNCE
			Reference reference = new Reference
			{
				Uri = nodeId,
#pragma warning disable 612
				DigestMethod = CPSignedXml.XmlDsigGost3411UrlObsolete
#pragma warning disable 612
			};

			XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
			reference.AddTransform(env);
			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			// Add the reference to the SignedXml object.
			signedXml.AddReference(reference);
			//----------------------------------------------------------------------------------------------SIGNATURE SETUP
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
			signedXml.SignedInfo.SignatureMethod = CPSignedXml.XmlDsigGost3410UrlObsolete;
			//----------------------------------------------------------------------------------------------KEYINFO
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			signedXml.KeyInfo = keyInfo;
			//----------------------------------------------------------------------------------------------SIGN DOCUMENT
			signedXml.ComputeSignature();
			//----------------------------------------------------------------------------------------------GET XML
			XmlElement xmlDigitalSignature = signedXml.GetXml();
			//----------------------------------------------------------------------------------------------APPEND SIGNATURE
			XmlNode root = doc.SelectSingleNode("/*");
			root?.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

			return doc;
		}
	}
}
