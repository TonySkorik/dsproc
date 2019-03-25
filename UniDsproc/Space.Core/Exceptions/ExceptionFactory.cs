using System;
using System.Collections.Generic;

namespace Space.Core.Exceptions
{
	internal enum ExceptionType
	{
		// signing
		PrivateKeyMissing,
		DsAssignmentNotSupported,
		NodeIdRequired,
		UnknownSigningException,
		CertExpired,
		CertificateKeyConversionFailed,

		// cetificate processing
		CertificateNotFoundByThumbprint,
		MoreThanOneCertificate,
		UnknownCertificateException,
		CertificateNotFoundByNodeId,
		Smev2CertificateReferenceNotFound,
		CertificateNotFound,
		SignatureNotFound,
		CertificateFileCorrupted,
		NoCertificatesFound,
		UnknownCertificateSource,

		// signature verification
		UnsupportedSignatureType,
		InputXmlMissingOrCorrupted,
		CertificateImportException,
		ReferencedSignatureNotFound,
		NoSignaturesFound,
		CertificateContentCorrupted,
		Smev2MalformedCertificateReference,
		Smev2CertificateNotFound,
		Smev2CertificateCorrupted,
		ChargeTooManySignaturesFound,
		ChargeMalformedDocument,
	}

	internal static class ExceptionFactory
	{
		private static readonly Dictionary<ExceptionType, string> Messages = new Dictionary<ExceptionType, string>()
		{
			// signing
			{ExceptionType.PrivateKeyMissing, "Certificate (subject: <{0}>) private key not found."},
			{
				ExceptionType.DsAssignmentNotSupported,
				"'ds:' prefix assignment is not supported for selected signature mode {mode}. Supported modes are : <smev3_base.detached>, <smev3_sidebyside.detached>, <smev3_ack>"
			},
			{ExceptionType.NodeIdRequired, "<node_id> value is empty. This value is required"},
			{ExceptionType.UnknownSigningException, "Unknown signing exception. Original message: {0}"},
			{ExceptionType.CertExpired, "Certificate with thumbprint <{0}> expired!"},
			{
				ExceptionType.CertificateKeyConversionFailed,
				"Certificate key is not valid for this signature algorithm!"
			}

			// cetificate processing
			,
			{ExceptionType.CertificateNotFoundByThumbprint, "Certificate with thumbprint {0} not found"},
			{ExceptionType.MoreThanOneCertificate, "More than one certificate with thumbprint {0} found!"},
			{ExceptionType.UnknownCertificateException, "Unknown certificate exception. Original message : {0}"},
			{
				ExceptionType.CertificateNotFoundByNodeId,
				"Certificate with node_id=<{0}> not found in passed document"
			},
			{ExceptionType.Smev2CertificateReferenceNotFound, "No certificate reference found in input file"},
			{ExceptionType.CertificateNotFound, "Certificate not found in passed document"},
			{ExceptionType.SignatureNotFound, "Signature not found in passed document"},
			{
				ExceptionType.CertificateFileCorrupted,
				"Input file appears to be corrupted or in wrong format. Message: {0}"
			},
			{ExceptionType.NoCertificatesFound, "Input certificate collection <{0}> appears to be empty"},
			{
				ExceptionType.UnknownCertificateSource,
				"Unknown certificate source passed. Possible values : <xml>, <base64>, <cer>"
			}

			// signature verification
			// 0 - signature mode
			,
			{
				ExceptionType.UnsupportedSignatureType,
				"Signature type <{0}> is unsupported. Possible values are : <smev2_base.enveloped>, <smev2_charge.enveloped>, <smev2_sidebyside.detached>, <smev3_base.detached>"
			}
			// 0 - filepath, 1 - exception message
			,
			{ExceptionType.InputXmlMissingOrCorrupted, "Input file <{0}> is invalid. Message: {1}"}
			// 0 - certificate file path, 1 - exception message
			,
			{ExceptionType.CertificateImportException, "Certificate <{0}> can not be loaded. Message: {1}"},
			{
				ExceptionType.ReferencedSignatureNotFound,
				"Referenced signature with node_id=<{0}> not found in the input file."
			},
			{ExceptionType.NoSignaturesFound, "No signatures found in the input file."}
			// 0 - exception message
			,
			{
				ExceptionType.CertificateContentCorrupted,
				"<X509Certificate> node content appears to be corrupted. Message: {0}"
			},
			{ExceptionType.Smev2MalformedCertificateReference, "Certificate reference appears to be malformed"}
			// 0 - binary token reference node
			,
			{ExceptionType.Smev2CertificateNotFound, "Referenced certificate not found. Reference: <{0}>"},
			{
				ExceptionType.Smev2CertificateCorrupted,
				"Smev2 certificate node content appears to be corrupted. Message: {0}"
			}
			// 0 - signatures in document count
			,
			{ExceptionType.ChargeTooManySignaturesFound, "More than one signature found. Found: {0} sigantures."},
			{
				ExceptionType.ChargeMalformedDocument,
				"Document structure is malformed. <Signature> node must be either root node descendant or root node descentant descendant."
			}
		};

		internal static Exception GetException(ExceptionType type, params object[] additionalInfo)
		{
			return new Exception($"{type.ToString().ToUpper()}] {string.Format(Messages[type], additionalInfo)}");
		}

	}
}
