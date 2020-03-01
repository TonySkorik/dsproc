using System.Net.Http;

namespace UniDsproc.Api.Helpers
{
	public static class HttpRequestHelper
	{
		public static string GetRemoteIp(this HttpRequestMessage targetRequest)
		{
			return targetRequest.GetOwinContext().Request.RemoteIpAddress;
		}

		public static bool IsAuthorized(this HttpRequestMessage request)
		{
			string remoteIp = request.GetRemoteIp();
			return Program.WebApiHost.IsIpAllowedToConnect(remoteIp);
		}
	}
}
