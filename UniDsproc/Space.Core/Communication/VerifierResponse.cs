using System;
using Newtonsoft.Json;

namespace Space.Core.Communication
{
	public class VerifierResponse
	{
		public bool IsSignatureMathematicallyValid { set; get; }

		public bool IsSignatureSigningDateValid { set; get; }

		/// <summary>
		/// Valid for detached binary signatures only. We do not return this as part othe verifier response.
		/// Instead we return this in the separate response part.
		/// </summary>
		[JsonIgnore]
		public DateTime? SigningDateTime { set; get; }

		public bool IsCertificateChainValid { set; get; } = true; // default value for cases when we do not need to check certificate chain

		public string Message { set; get; }

		[JsonProperty("IsSignatureValid")]
		public bool IsSignatureValid =>
			IsSignatureMathematicallyValid 
			&& IsSignatureSigningDateValid 
			&& IsCertificateChainValid;

		public static VerifierResponse Invalid(string message) => new VerifierResponse()
		{
			IsSignatureMathematicallyValid = false,
			IsSignatureSigningDateValid = false,
			IsCertificateChainValid = false,
			Message = message
		};

		public static VerifierResponse Valid => new VerifierResponse()
		{
			IsSignatureMathematicallyValid = true,
			IsSignatureSigningDateValid = true,
			IsCertificateChainValid = true,
			Message = "Signature is valid"
		};
	}
}
