using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Space.Core.Communication;
using UniDsproc.Api.Helpers;

namespace UniDsproc.Api.Model
{
	internal class OperationContext
	{
		public HttpRequestMessage Request { get; }
		public string RawInputParameters { private set; get; }
		public ApiInputParameters InputParameters { private set; get; }
		public SignerResponse SignerResponse { private set; get; }
		public int ReturnedStatusCode { private set; get; }
		public string ExceptionMessage { private set; get; }

		public OperationContext(HttpRequestMessage request)
		{
			Request = request;
		}

		public void SetRawInputParameters(string parametersString, string command)
		{
			RawInputParameters = $"{command}/{parametersString}";
		}

		public void SetInputParameters(ApiInputParameters parameters)
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
