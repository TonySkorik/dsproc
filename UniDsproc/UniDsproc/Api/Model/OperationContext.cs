using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Space.Core.Communication;

namespace UniDsproc.Api.Model
{
	internal class OperationContext
	{
		private DateTime RequestDateTime { get; } = DateTime.Now;
		public string RawInputParameters { private set; get; }
		public SignerInputParameters InputParameters { private set; get; }
		public SignerResponse SignerResponse { private set; get; }
		public int ReturnedStatusCode { private set; get; }
		public string ExceptionMessage { private set; get; }

		public void SetRawInputParameters(string parametersString, string command)
		{
			RawInputParameters = $"{command}/{parametersString}";
		}

		public void SetInputParameters(SignerInputParameters parameters)
		{
			InputParameters = parameters;
		}

		public void SetStatusCode(HttpStatusCode code)
		{
			ReturnedStatusCode = (int)code;
		}

		public void SetException(Exception exception)
		{
			ExceptionMessage = exception.Message;
		}

		public void SetSignerResponse(SignerResponse response)
		{
			SignerResponse = response;
		}
	}
}
