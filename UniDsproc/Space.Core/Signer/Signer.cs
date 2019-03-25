﻿using System;
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
using Space.Core.Configuration;
using Space.Core.Exceptions;
using Space.Core.Extensions;
using Space.Core.Interfaces;

namespace Space.Core
{
	public partial class Signer : ISigner
	{
		#region Public ISigner methods

		public string Sign(
			SignatureType mode,
			XDocument signThis,
			string certificateThumbprint,
			string nodeToSign,
			bool assignDs = false,
			bool ignoreExpiredCert = false)
		{
			return Sign(mode, certificateThumbprint, signThis.GetXmlDocument(), assignDs, nodeToSign, ignoreExpiredCert);
		}

		public string Sign(
			SignatureType mode,
			XmlDocument signThis,
			string certificateThumbprint,
			string nodeToSign,
			bool assignDs = false,
			bool ignoreExpiredCert = false)
		{
			return Sign(mode, certificateThumbprint, signThis, assignDs, nodeToSign, ignoreExpiredCert);
		}

		public string Sign(
			SignatureType mode,
			string certificateThumbprint,
			string signThisPath,
			bool assignDs,
			string nodeToSign,
			bool ignoreExpiredCert = false)
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
			else if (mode == SignatureType.SigDetached)
			{
				bytesToSign = File.ReadAllBytes(signThisPath);
			}
			else
			{
				signThis = new XmlDocument();
				signThis.Load(signThisPath);
			}
			return Sign(mode, certificateThumbprint, signThis, assignDs, nodeToSign, ignoreExpiredCert, stringToSign, bytesToSign);
		}

		#endregion

		#region Methods for signature type selection and data preparation

		private string Sign(
			SignatureType mode,
			string certificateThumbprint,
			XmlDocument signThis,
			bool assignDs,
			string nodeToSign,
			bool ignoreExpiredCert = false,
			string stringToSign = null,
			byte[] bytesToSign = null)
		{
			ICertificateProcessor cp = new CertificateProcessor();
			X509Certificate2 certificate = cp.SearchCertificateByThumbprint(certificateThumbprint);

			if (!certificate.HasPrivateKey)
			{
				throw ExceptionFactory.GetException(ExceptionType.PrivateKeyMissing, certificate.Subject);
			}

			if (!ignoreExpiredCert && cp.IsCertificateExpired(certificate))
			{
				throw ExceptionFactory.GetException(ExceptionType.CertExpired, certificate.Thumbprint);
			}

			return Sign(mode, certificate, signThis, assignDs, nodeToSign, stringToSign, bytesToSign);
		}

		private string Sign(
			SignatureType mode,
			X509Certificate2 cert,
			XmlDocument signThis,
			bool assignDs,
			string nodeToSign,
			string stringToSign = null,
			byte[] bytesToSign = null)
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
						signedXmlDoc = SignXmlNode(signThis, cert, nodeToSign);
						break;
					case SignatureType.Smev2ChargeEnveloped:
						signedXmlDoc = SignXmlFileEnveloped(signThis, cert);
						break;
					case SignatureType.Smev2BaseDetached:
						signedXmlDoc = SignXmlFileSmev2(signThis, cert);
						break;

					case SignatureType.Smev3BaseDetached:
						if (string.IsNullOrEmpty(nodeToSign))
						{
							throw ExceptionFactory.GetException(ExceptionType.NodeIdRequired);
						}
						signedXmlDoc = SignXmlFileSmev3(signThis, cert, nodeToSign, assignDs);
						break;
					case SignatureType.Smev3SidebysideDetached:
						if (string.IsNullOrEmpty(nodeToSign))
						{
							throw ExceptionFactory.GetException(ExceptionType.NodeIdRequired);
						}
						signedXmlDoc = SignXmlFileSmev3(signThis, cert, nodeToSign, assignDs, isAck: false, isSidebyside: true);
						break;
					case SignatureType.Smev3Ack:
						if (string.IsNullOrEmpty(nodeToSign))
						{
							throw ExceptionFactory.GetException(ExceptionType.NodeIdRequired);
						}
						signedXmlDoc = SignXmlFileSmev3(signThis, cert, nodeToSign, assignDs, isAck: true);
						break;

					case SignatureType.SigDetached:
						return Convert.ToBase64String(SignPkcs7(bytesToSign, cert, X509IncludeOption.EndCertOnly));
					case SignatureType.SigDetachedNoCert:
						return Convert.ToBase64String(SignPkcs7(bytesToSign, cert, X509IncludeOption.None));
					case SignatureType.SigDetachedAllCert:
						return Convert.ToBase64String(SignPkcs7(bytesToSign, cert, X509IncludeOption.WholeChain));

					case SignatureType.Pkcs7String:
						return Convert.ToBase64String(SignStringPkcs7(stringToSign, cert, X509IncludeOption.EndCertOnly));
					case SignatureType.Pkcs7StringNoCert:
						return Convert.ToBase64String(SignStringPkcs7(stringToSign, cert, X509IncludeOption.None));
					case SignatureType.Pkcs7StringAllCert:
						return Convert.ToBase64String(SignStringPkcs7(stringToSign, cert, X509IncludeOption.WholeChain));

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