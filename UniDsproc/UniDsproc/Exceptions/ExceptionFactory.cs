using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace UniDsproc.Exceptions {
	public enum ExceptionType
	{
		// signing
		PRIVATE_KEY_MISSING,
		DS_ASSIGNMENT_NOT_SUPPORTED,
		NODE_ID_REQUIRED,
		UNKNOWN_SIGNING_EXCEPTION,
		CERT_EXPIRED,

		// cetificate processing
		CERTIFICATE_NOT_FOUND_BY_THUMBPRINT,
		MORE_THAN_ONE_CERTIFICATE,
		UNKNOWN_CERTIFICATE_EXCEPTION,
		CERTIFICATE_NOT_FOUND_BY_NODE_ID,
		SMEV2_CERTIFICATE_REFERENCE_NOT_FOUND,
		CERTIFICATE_NOT_FOUND,
		SIGNATURE_NOT_FOUND,
		CERTIFICATE_FILE_CORRUPTED,
		NO_CERTIFICATES_FOUND,
		UNKNOWN_CERTIFICATE_SOURCE,

		// signature verification
		UNSUPPORTED_SIGNATURE_TYPE,
		INPUT_XML_MISSING_OR_CORRUPTED,
		CERTIFICATE_IMPORT_EXCEPTION,
		REFERENCED_SIGNATURE_NOT_FOUND,
		NO_SIGNATURES_FOUND,
		CERTIFICATE_CONTENT_CORRUPTED,
		SMEV2_MALFORMED_CERTIFICATE_REFERENCE,
		SMEV2_CERTIFICATE_NOT_FOUND,
		SMEV2_CERTIFICATE_CORRUPTED,
		CHARGE_TOO_MANY_SIGNATURES_FOUND,
		CHARGE_MALFORMED_DOCUMENT,
	}

	public static class ExceptionFactory
	{
		private static Dictionary<ExceptionType, string> _messages = new Dictionary<ExceptionType, string>() {
			// signing
			{ExceptionType.PRIVATE_KEY_MISSING, "PRIVATE_KEY_MISSING] Certificate (subject: <{0}>) private key not found."}
			, {ExceptionType.DS_ASSIGNMENT_NOT_SUPPORTED, "'ds:' prefix assignment is not supported for selected signature mode {mode}. Supported modes are : <smev3_base.detached>, <smev3_sidebyside.detached>, <smev3_ack>"}
			, {ExceptionType.NODE_ID_REQUIRED, "<node_id> value is empty. This value is required"}
			, {ExceptionType.UNKNOWN_SIGNING_EXCEPTION, "Unknown signing exception. Original message: {0}"}
			, {ExceptionType.CERT_EXPIRED, "Certificate with thumbprint <{0}> expired!"}

			// cetificate processing
			, {ExceptionType.CERTIFICATE_NOT_FOUND_BY_THUMBPRINT, "Certificate with thumbprint {0} not found"}
			, {ExceptionType.MORE_THAN_ONE_CERTIFICATE, "More than one certificate with thumbprint {0} found!"}
			, {ExceptionType.UNKNOWN_CERTIFICATE_EXCEPTION, "Unknown certificate exception. Original message : {0}"}
			, {ExceptionType.CERTIFICATE_NOT_FOUND_BY_NODE_ID, "Certificate with node_id=<{0}> not found in passed document"}
			, {ExceptionType.SMEV2_CERTIFICATE_REFERENCE_NOT_FOUND, "No certificate reference found in input file"}
			, {ExceptionType.CERTIFICATE_NOT_FOUND, "Certificate not found in passed document"}
			, {ExceptionType.SIGNATURE_NOT_FOUND, "Signature not found in passed document"}
			, {ExceptionType.CERTIFICATE_FILE_CORRUPTED, "Input file appears to be corrupted or in wrong format. Message: {0}"}
			, {ExceptionType.NO_CERTIFICATES_FOUND, "Input certificate collection <{0}> appears to be empty"}
			, {ExceptionType.UNKNOWN_CERTIFICATE_SOURCE, "Unknown certificate source passed. Possible values : <xml>, <base64>, <cer>"}

			// signature verification
			// 0 - signature mode
			, {ExceptionType.UNSUPPORTED_SIGNATURE_TYPE, "Signature type <{0}> is unsupported. Possible values are : <smev2_base.enveloped>, <smev2_charge.enveloped>, <smev2_sidebyside.detached>, <smev3_base.detached>"}
			// 0 - filepath, 1 - exception message
			, {ExceptionType.INPUT_XML_MISSING_OR_CORRUPTED, "Input file <{0}> is invalid. Message: {1}"}
			// 0 - certificate file path, 1 - exception message
			, {ExceptionType.CERTIFICATE_IMPORT_EXCEPTION, "Certificate <{0}> can not be loaded. Message: {1}"}
			, {ExceptionType.REFERENCED_SIGNATURE_NOT_FOUND, "Referenced signature with node_id=<{0}> not found in the input file."}
			, {ExceptionType.NO_SIGNATURES_FOUND, "No signatures found in the input file."}
			// 0 - exception message
			, {ExceptionType.CERTIFICATE_CONTENT_CORRUPTED, "<X509Certificate> node content appears to be corrupted. Message: {0}"}
			, {ExceptionType.SMEV2_MALFORMED_CERTIFICATE_REFERENCE, "Certificate reference appears to be malformed"}
			// 0 - binary token reference node
			, {ExceptionType.SMEV2_CERTIFICATE_NOT_FOUND, "Referenced certificate not found. Reference: <{0}>"}
			, {ExceptionType.SMEV2_CERTIFICATE_CORRUPTED, "Smev2 certificate node content appears to be corrupted. Message: {0}"}
			// 0 - signatures in document count
			, {ExceptionType.CHARGE_TOO_MANY_SIGNATURES_FOUND, "More than one signature found. Found: {0} sigantures."}
			, {ExceptionType.CHARGE_MALFORMED_DOCUMENT, "Document structure is malformed. <Signature> node must be either root node descendant or root node descentant descendant."}

		};

		public static Exception GetException(ExceptionType type, params object[] additionalInfo)
		{
			return new Exception($"{type.ToString().ToUpper()}] {String.Format(_messages[type],additionalInfo)}");
		}

	}
}
