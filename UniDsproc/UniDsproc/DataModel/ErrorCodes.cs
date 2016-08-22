using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UniDsproc.DataModel {
	public static class ErrorCodes {
		#region [CONFIG PARSING]
		public static string ArgumentInvalidValue = "ARGUMENT_INVALID_VALUE";
		public static string ArgumentNullValue = "ARGUMENT_NULL_VALUE";
		public static string UnknownArgument = "UNKNOWN_ARGUMENT";
		public static string UnknownFunction = "UNKNOWN_COMMAND";
		public static string FileNotExist = "FILE_NOT_FOUND";
		#endregion

		#region [SIGNING]
		public static string SigningFailed = "SIGNING_FAILED";
		#endregion

		#region [SIGNATURE VERIFICATION]

		public static string VerificationFailed = "SIGNATURE_VERIFICATION_FAILED";
		#endregion

		#region [CERT EXTRACTION]
		public static string CertificateExtractionException = "CERTIFICATE_EXTRACTION_EXCEPTION";
		
		#endregion

		#region [UNKNOWN EXCEPTIONS]
		public static string UnknownException = "UNKNOWN_EXCEPTION";
		#endregion

	}
}
