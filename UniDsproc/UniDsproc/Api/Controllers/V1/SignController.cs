using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Xml.Linq;
using Serilog;
using UniDsproc.Api.Helpers;
using UniDsproc.Api.Infrastructure;
using UniDsproc.Api.Model;

namespace UniDsproc.Api.Controllers.V1
{
	[RoutePrefix("api/v1/sign")]
	public class SignController : ApiController
	{
		[HttpGet]
		public async Task<IHttpActionResult> Sign()
		{
			
		}

		[HttpPost]
		[Route("")]
		public async Task<IHttpActionResult> Respond()
		{
			// Returning following statuses
			// + 200 + 0 if all OK (output contains XML output);
			// + 400 + 5 any parameter validation error
			// + 417 + 4 Message from SMEV is not OK
			// + 500 + 6 any exception in unismev : 6 Error happened before sending data to SMEV (see stdout for more details)
			// + 408 + 7 Cancellation
			
			if (!Request.IsAuthorized())
			{
				Log.Logger.Information($"Blocked WebApiHost request from {Request.GetRemoteIp()}.");
				return StatusCode(HttpStatusCode.Forbidden);
			}

			Program.WebApiHost.ClientConnected();
			
			var responderParameters = await ReadResponderParameters(Request);
			var validationResult = ValidateParameters(responderParameters);

			if (!validationResult.isParametersOk)
			{
				return BadRequest(validationResult.errorReason);
			}

			try
			{
				SmevMessageSendStatus sendStatus = await EntryPointsManager.SendMessageViaResponder(responderParameters);
				return sendStatus.AnalyzeMessageSendStatus(this);
			}
			catch (Exception ex)
			{
				//means something gone wrong
				SmevClient.WriteToSystemLog(
					new EventEntry(
						EventType.Error,
						$"Responder message processing failed",
						null,
						false
					)
					{
						DetailsContent = ex.ToString()
					}
				);

				return BadRequest("Exception happened during Reponder API processing.");
			}
			finally
			{
				EntryPointsManager.SignalBusinessOperationCompletion(operationId);
				Program.WebApiHost.ClientDisconnected();
			}
		}

		#region Test methods

		[HttpGet]
		[Route("test")]
		public async Task<IHttpActionResult> Test()
		{
			Program.WebApiHost.ClientConnected();
			await Task.Delay(TimeSpan.FromSeconds(1));
			Program.WebApiHost.ClientDisconnected();
			return Json(DateTime.UtcNow);
		}

		#endregion

		#region Service methods
		
		private (bool isParametersOk, string errorReason) ValidateParameters(ResponderInputParameters parameters)
		{
			if (parameters.CommandType == ResponderCommandType.Unknown)
			{
				return (false, $"Unknown command type.");
			}

			if (string.IsNullOrEmpty(parameters.GroupNick))
			{
				return (false, $"Group nick is empty.");
			}

			if (string.IsNullOrEmpty(parameters.GroupNick))
			{
				return (false, $"Group nick is empty.");
			}

			if (parameters.BusinessData == null)
			{
				return (false, $"Message XML is malformed.");
			}

			return (true, string.Empty);
		}

		private async Task<SignerInputParameters> ReadResponderParameters(HttpRequestMessage request)
		{
			var clientDisconnected = request.GetOwinContext()?.Request?.CallCancelled ?? CancellationToken.None;

			//NOTE: this is not an in-memory way of doing the same thing
			//var root = HttpContext.Current.Server.MapPath("~/App_Data/");
			//var streamProvider = new MultipartFormDataStreamProvider(root);

			var streamProvider = new InMemoryMultipartFormDataStreamProvider();
			await request.Content.ReadAsMultipartAsync(streamProvider, clientDisconnected);

			var parameters = request.RequestUri.ParseQueryString();

			Enum.TryParse(streamProvider.FormData["type"], true, out ResponderCommandType commandType);
			
			ResponderInputParameters responderParameters = new ResponderInputParameters()
			{
				CommandType = commandType,
				GroupNick = streamProvider.FormData["group"],
				ReplyTo = streamProvider.FormData["reply_to"],
				CancellationToken = clientDisconnected
			};

			var messageXmlFile = streamProvider.Files.FirstOrDefault(f => f.Headers.ContentDisposition.Name == "message_xml");
			if (messageXmlFile != null)
			{
				(await messageXmlFile.ReadAsStringAsync()).TryParseAsXml(out XDocument businessData);
				responderParameters.BusinessData = businessData;
			}

			var fileListFile =
				streamProvider.Files.FirstOrDefault(f => f.Headers.ContentDisposition.Name == "filelist");
			if (fileListFile != null)
			{
				var fileListContent = await fileListFile.ReadAsStringAsync();
				responderParameters.FileList = FileList2.Parse(fileListContent);
			}

			return responderParameters;
		}
		
		#endregion
	}
}
