using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using CryptoPro.Sharpei.Xml;
using Space.Core.Infrastructure;

namespace Space.Core
{
	/// <summary>
	/// Simple node sign
	/// </summary>
	/// <seealso cref="Space.Core.Interfaces.ISigner" />
	public partial class Signer
	{
		private XmlNode GetNodeWithAttributeValue(XmlNodeList nodelist, string attributeValue)
		{
			XmlNode ret = null;
			foreach (XmlNode xn in nodelist)
			{
				if (xn.HasChildNodes)
				{
					ret = GetNodeWithAttributeValue(xn.ChildNodes, attributeValue);
					if (ret != null) break;
				}
				if (xn.Attributes != null && xn.Attributes.Count != 0)
				{
					foreach (XmlAttribute xa in xn.Attributes)
					{
						if (xa.Value == attributeValue)
						{
							ret = xn;
							break;
						}
					}
				}
			}
			return ret;
		}

		private XmlDocument SignXmlNode(GostFlavor gostFlavor, XmlDocument doc, X509Certificate2 certificate, string nodeId)
		{
			//----------------------------------------------------------------------------------------------CREATE SIGNED XML
			SignedXml signedXml = new SignedXml(doc)
			{
				SigningKey = certificate.PrivateKey
			};
			//----------------------------------------------------------------------------------------------REFERNCE
			Reference reference = new Reference
			{
				Uri = "#" + nodeId,
#pragma warning disable 612
				DigestMethod = GostAlgorithmSelector.GetHashAlgorithmDescriptor(gostFlavor)
					//CPSignedXml.XmlDsigGost3411UrlObsolete - old
#pragma warning disable 612
			};

			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			// Add the reference to the SignedXml object.
			signedXml.AddReference(reference);
			//----------------------------------------------------------------------------------------------SIGNATURE SETUP
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
			signedXml.SignedInfo.SignatureMethod = GostAlgorithmSelector.GetSignatureAlgorithmDescriptor(gostFlavor);
				//CPSignedXml.XmlDsigGost3410UrlObsolete;
			//----------------------------------------------------------------------------------------------KEYINFO
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data x509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(x509KeyInfo);
			signedXml.KeyInfo = keyInfo;
			//----------------------------------------------------------------------------------------------SIGN DOCUMENT
			signedXml.ComputeSignature();
			//----------------------------------------------------------------------------------------------GET XML
			XmlElement xmlDigitalSignature = signedXml.GetXml();
			//=============================================================================APPEND SIGNATURE TO DOCUMENT

			GetNodeWithAttributeValue(doc.ChildNodes, nodeId)?.ParentNode?.AppendChild(xmlDigitalSignature);

			return doc;
		}
	}
}
