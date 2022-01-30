using System;
using System.IO;
using System.Xml;
using Space.Core.Communication;
using Space.Core.Exceptions;
using Space.Core.Verifier;

namespace Space.Core.Model.SignedFile
{
	public class SignedXmlFile : InputDataBase
	{
		public string NodeId { get; set; }

		public override VerifierResponse Verify(IVerifier verifier, SignatureVerificationParameters parameters)
		{
			return verifier.Verify(this, parameters);
		}

		public XmlDocument GetXmlDocument()
		{
			XmlDocument ret = new XmlDocument();

			if (FilePath != null)
			{
				try
				{
					ret.Load(FilePath);
				}
				catch (Exception e)
				{
					throw ExceptionFactory.GetException(
						ExceptionType.InputXmlMissingOrCorrupted,
						FilePath,
						e.Message);
				}
			}
			else
			{
				if (FileBytes == null)
				{
					throw new InvalidOperationException("Signed file data is not provided.");
				}

				ret.Load(new MemoryStream(FileBytes));
			}

			return ret;
		}
	}
}
