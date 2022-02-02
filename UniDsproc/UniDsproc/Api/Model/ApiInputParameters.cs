using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UniDsproc.DataModel;

namespace UniDsproc.Api.Model
{
	internal class ApiInputParameters
	{
		public ArgsInfo ArgsInfo { set; get; }
		
		public byte[] DataToSign { set; get; }
		
		public byte[] SignatureFileBytes { set; get; }

		public byte[] CertificateFileBytes { set; get; }
	}
}
