using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Space.Core.Communication
{
	public class SignerResponse
	{
		public string SignedData { get; }
		public bool IsResultBase64Bytes { get; }

		public SignerResponse(string signedData, bool isResultBase64Bytes)
		{
			SignedData = signedData;
			IsResultBase64Bytes = isResultBase64Bytes;
		}
	}
}
