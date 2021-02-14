using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using CryptoPro.Sharpei.Xml;
using Space.Core.Communication;
using Space.Core.Configuration;
using Space.Core.Exceptions;
using Space.Core.Extensions;
using Space.Core.Infrastructure;
using Space.Core.Interfaces;
using Space.Core.Processor;

namespace Space.Core
{
	public partial class Signer : ISigner
	{
		#region Public ISigner methods

		public string Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			XDocument signThis,
			string certificateThumbprint,
			string nodeToSign,
			bool assignDs = false,
			bool ignoreExpiredCert = false,
			bool? isAddSigningTime = null)
		{
			return Sign(
				mode,
				gostFlavor,
				certificateThumbprint,
				signThis.GetXmlDocument(),
				assignDs,
				nodeToSign,
				ignoreExpiredCert, 
				isAddSigningTime: isAddSigningTime);
		}

		public string Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			XmlDocument signThis,
			string certificateThumbprint,
			string nodeToSign,
			bool assignDs = false,
			bool ignoreExpiredCert = false,
			bool? isAddSigningTime = null)
		{
			return Sign(mode, gostFlavor, certificateThumbprint, signThis, assignDs, nodeToSign, ignoreExpiredCert, isAddSigningTime: isAddSigningTime);
		}

		public SignerResponse Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			string certificateThumbprint,
			byte[] bytesToSign,
			string nodeToSign,
			bool ignoreExpiredCert = false,
			bool? isAddSigningTime = null)
		{
			XmlDocument signThis = null;
			string stringToSign = null;
			bool isResultBase64Bytes = false;

			if (mode == SignatureType.Pkcs7String
				|| mode == SignatureType.Pkcs7StringAllCert
				|| mode == SignatureType.Pkcs7StringNoCert

				|| mode == SignatureType.Rsa2048Sha256String
				|| mode == SignatureType.RsaSha256String)
			{
				stringToSign = Encoding.UTF8.GetString(bytesToSign);
				isResultBase64Bytes = true;
			}
			else
			{
				signThis = new XmlDocument();
				var stringContent = Encoding.UTF8.GetString(bytesToSign);
				signThis.LoadXml(stringContent);
			}

			var signedData = Sign(
				mode,
				gostFlavor,
				certificateThumbprint,
				signThis,
				false,
				nodeToSign,
				ignoreExpiredCert,
				stringToSign,
				string.IsNullOrEmpty(stringToSign)
					? bytesToSign
					: null,
				isAddSigningTime);

			return new SignerResponse(signedData, isResultBase64Bytes);
		}
		
		public string Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			string certificateThumbprint,
			string signThisPath,
			bool assignDs,
			string nodeToSign,
			bool ignoreExpiredCert = false,
			bool? isAddSigningTime = null)
		{
			XmlDocument signThis = null;
			string stringToSign = null;
			byte[] bytesToSign = null;

			if (
				assignDs
				&& !new List<SignatureType>()
				{
					SignatureType.Smev3BaseDetached,
					SignatureType.Smev3SidebysideDetached,
					SignatureType.Smev3Ack
				}.Contains(mode))
			{
				throw ExceptionFactory.GetException(ExceptionType.DsAssignmentNotSupported);
			}

			if (mode == SignatureType.Pkcs7String
				|| mode == SignatureType.Pkcs7StringAllCert
				|| mode == SignatureType.Pkcs7StringNoCert

				|| mode == SignatureType.Rsa2048Sha256String
				|| mode == SignatureType.RsaSha256String)
			{
				stringToSign = File.ReadAllText(signThisPath, Encoding.UTF8);
			}
			else if (mode == SignatureType.SigDetached
				|| mode == SignatureType.SigDetachedAllCert
				|| mode == SignatureType.SigDetachedNoCert)
			{
				bytesToSign = File.ReadAllBytes(signThisPath);
			}
			else
			{
				signThis = new XmlDocument();
				signThis.Load(signThisPath);
			}

			return Sign(
				mode,
				gostFlavor,
				certificateThumbprint,
				signThis,
				assignDs,
				nodeToSign,
				ignoreExpiredCert,
				stringToSign,
				bytesToSign,
				isAddSigningTime);
		}

		#endregion

		#region Methods for signature type selection and data preparation

		private string Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			string certificateThumbprint,
			XmlDocument signThis,
			bool assignDs,
			string nodeToSign,
			bool ignoreExpiredCert = false,
			string stringToSign = null,
			byte[] bytesToSign = null,
			bool? isAddSigningTime = null)
		{
			ICertificateProcessor cp = new CertificateProcessor();
			X509Certificate2 certificate = cp.SearchCertificateByThumbprint(certificateThumbprint);

			if (!certificate.HasPrivateKey)
			{
				throw ExceptionFactory.GetException(ExceptionType.PrivateKeyMissing, certificate.Subject);
			}

			if (!ignoreExpiredCert
				&& cp.IsCertificateExpired(certificate))
			{
				throw ExceptionFactory.GetException(ExceptionType.CertExpired, certificate.Thumbprint);
			}

			return Sign(mode, gostFlavor, certificate, signThis, assignDs, nodeToSign, stringToSign, bytesToSign, isAddSigningTime);
		}

		private string Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			X509Certificate2 cert,
			XmlDocument signThis,
			bool assignDs,
			string nodeToSign,
			string stringToSign = null,
			byte[] bytesToSign = null,
			bool? isAddSigningTime = null)
		{

			XmlDocument signedXmlDoc = new XmlDocument();

			try
			{
				switch (mode)
				{
					case SignatureType.Smev2SidebysideDetached:
						if (string.IsNullOrEmpty(nodeToSign))
						{
							throw ExceptionFactory.GetException(ExceptionType.NodeIdRequired);
						}

						signedXmlDoc = SignXmlNode(gostFlavor, signThis, cert, nodeToSign);
						break;
					case SignatureType.Smev2ChargeEnveloped:
						signedXmlDoc = SignEnveloped(gostFlavor, signThis, cert);
						break;
					case SignatureType.Smev2BaseDetached:
						signedXmlDoc = SignSmev2(gostFlavor, signThis, cert);
						break;

					case SignatureType.Smev3BaseDetached:
						if (string.IsNullOrEmpty(nodeToSign))
						{
							throw ExceptionFactory.GetException(ExceptionType.NodeIdRequired);
						}

						signedXmlDoc = SignSmev3(gostFlavor, signThis, cert, nodeToSign, assignDs);
						break;
					case SignatureType.Smev3SidebysideDetached:
						if (string.IsNullOrEmpty(nodeToSign))
						{
							throw ExceptionFactory.GetException(ExceptionType.NodeIdRequired);
						}

						signedXmlDoc = SignSmev3(
							gostFlavor,
							signThis,
							cert,
							nodeToSign,
							assignDs,
							isAck: false,
							isSidebyside: true);
						break;
					case SignatureType.Smev3Ack:
						if (string.IsNullOrEmpty(nodeToSign))
						{
							throw ExceptionFactory.GetException(ExceptionType.NodeIdRequired);
						}

						signedXmlDoc = SignSmev3(gostFlavor, signThis, cert, nodeToSign, assignDs, isAck: true);
						break;

					case SignatureType.SigDetached:
						return Convert.ToBase64String(SignPkcs7(bytesToSign, cert, X509IncludeOption.EndCertOnly, isAddSigningTime ?? false));
					case SignatureType.SigDetachedNoCert:
						return Convert.ToBase64String(SignPkcs7(bytesToSign, cert, X509IncludeOption.None, isAddSigningTime ?? false));
					case SignatureType.SigDetachedAllCert:
						return Convert.ToBase64String(SignPkcs7(bytesToSign, cert, X509IncludeOption.WholeChain, isAddSigningTime ?? false));

					case SignatureType.Pkcs7String:
						return Convert.ToBase64String(
							SignStringPkcs7(stringToSign, cert, X509IncludeOption.EndCertOnly, isAddSigningTime ?? false));
					case SignatureType.Pkcs7StringNoCert:
						return Convert.ToBase64String(SignStringPkcs7(stringToSign, cert, X509IncludeOption.None, isAddSigningTime ?? false));
					case SignatureType.Pkcs7StringAllCert:
						return Convert.ToBase64String(
							SignStringPkcs7(stringToSign, cert, X509IncludeOption.WholeChain, isAddSigningTime ?? false));

					case SignatureType.Rsa2048Sha256String:
						return Convert.ToBase64String(SignStringRsa2048Sha256(stringToSign, cert));
					case SignatureType.RsaSha256String:
						return Convert.ToBase64String(SignStringRsaSha(stringToSign, cert, ShaAlgorithmType.Sha256));
				}
			}
			catch (Exception e)
			{
				throw ExceptionFactory.GetException(ExceptionType.UnknownSigningException, e.Message);
			}

			return signedXmlDoc.InnerXml;
		}

		#endregion
	}
}
