using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Instrumentation;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Results;
using System.Xml.Linq;
using Serilog;
using Space.Core;
using Space.Core.Communication;
using Space.Core.Interfaces;
using UniDsproc.Api.Helpers;
using UniDsproc.Api.Infrastructure;
using UniDsproc.Api.Model;
using UniDsproc.Configuration;
using UniDsproc.DataModel;

namespace UniDsproc.Api.Controllers.V1
{
	[RoutePrefix("api/v1")]
	public class CommandController : ApiController
	{
		private readonly AppSettings _settings;
		private readonly ISigner _signer;
		
		public CommandController(AppSettings settings, ISigner signer)
		{
			_settings = settings;
			_signer = signer;
		}

		[HttpPost]
		[Route(("{command}"))]
		public async Task<IHttpActionResult> Command(string command)
		{
			if (!Request.IsAuthorized())
			{
				Log.Fatal("Blocked WebApiHost request from {blockedIp}.", Request.GetRemoteIp());
				return StatusCode(HttpStatusCode.Forbidden);
			}

			var context = new OperationContext();
			
			try
			{
				Program.WebApiHost.ClientConnected();

				var inputParameters = await ReadSignerParameters(Request, command, context);
				
				context.SetInputParameters(inputParameters);

				var validationResult = ValidateParameters(inputParameters);

				if (!validationResult.isParametersOk)
				{
					return ErrorResultBadRequest(validationResult.errorReason, context);
				}
				
				switch (inputParameters.ArgsInfo.Function)
				{
					case ProgramFunction.Sign:
						var signerResponse = _signer.Sign(
							inputParameters.ArgsInfo.SigType,
							inputParameters.ArgsInfo.GostFlavor,
							inputParameters.ArgsInfo.CertificateThumbprint,
							inputParameters.DataToSign,
							inputParameters.ArgsInfo.NodeId,
							inputParameters.ArgsInfo.IgnoreExpiredCertificate,
							inputParameters.ArgsInfo.IsAddSigningTime);
						
						var binaryData = signerResponse.IsResultBase64Bytes
							? Convert.FromBase64String(signerResponse.SignedData)
							: Encoding.UTF8.GetBytes(signerResponse.SignedData);

						context.SetSignerResponse(signerResponse);

						var streamToReturn = new MemoryStream(binaryData);

						var returnMessage= new HttpResponseMessage(HttpStatusCode.OK)
						{
							Content = new StreamContent(streamToReturn),
						};

						returnMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
						returnMessage.Headers.Add("UniApp", "UnDsProc");
						returnMessage.Headers.Add("UniVersion", Program.Version);

						Log.Debug(
							"Successfully signed file from ip {requesterIp} with following parameters: [{parameters}]",
							Request.GetRemoteIp(),
							inputParameters.ArgsInfo.ToString());

						return SuccessResult(returnMessage, context);
					default:
						return ErrorResultBadRequest($"Command {command} not supported.", context);
				}
			}
			catch (OperationCanceledException opce)
			{
				Log.Warning("Client disconnected prior to singing completion.");
				return ErrorResultBadRequest(opce, context);
			}
			catch (Exception ex)
			{
				Log.Error(ex, "Error occured during signing process with command: {command}", command);
				return ErrorResultBadRequest(ex, context);
			}
			finally
			{
				SaveOperationContext(context);
				Program.WebApiHost.ClientDisconnected();
			}
		}

		#region Methods for creating responses

		private IHttpActionResult SuccessResult(HttpResponseMessage message, OperationContext context)
		{
			context.SetStatusCode(message.StatusCode);
			return ResponseMessage(message);
		}

		private IHttpActionResult ErrorResultBadRequest(Exception exception, OperationContext context)
		{
			context.SetException(exception);
			return ErrorResultBadRequest(exception.Message, context);
		}

		private IHttpActionResult ErrorResultBadRequest(string message, OperationContext context)
		{
			context.SetStatusCode(HttpStatusCode.BadRequest);
			return BadRequest(message);
		}

		#endregion

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
		
		private void SaveOperationContext(OperationContext context)
		{
			if (!_settings.Logger.IsVerboseModeOn)
			{
				return;
			}

			var now = DateTime.Now;
			string path = $"data\\{now.Year:D4}\\{now.Month:D2}\\{now.Day:D2}\\{now.Hour:D2}-{now.Minute:D2}-{now.Second:D2}_{now.Millisecond:D3}";
			Directory.CreateDirectory(path);

			string requestParametersFileName = Path.Combine(path, "parameters.txt");
			string inputDataFileName = Path.Combine(path, "input.bin");
			string outputDataFileName = Path.Combine(path, $"output.{context.ReturnedStatusCode}");

			File.WriteAllText(requestParametersFileName, context.RawInputParameters);
			File.WriteAllBytes(inputDataFileName, context.InputParameters?.DataToSign ?? new byte[0]);
			File.WriteAllText(outputDataFileName, context.SignerResponse?.SignedData ?? context.ExceptionMessage);
		}

		private (bool isParametersOk, string errorReason) ValidateParameters(SignerInputParameters parameters)
		{
			if (parameters.DataToSign == null)
			{
				return (false, $"No data to sign.");
			}

			return (true, string.Empty);
		}

		private async Task<SignerInputParameters> ReadSignerParameters(HttpRequestMessage request, string command, OperationContext context)
		{
			context.SetRawInputParameters(request.RequestUri.Query, command);
			var clientDisconnected = request.GetOwinContext()?.Request?.CallCancelled ?? CancellationToken.None;

			//NOTE: this is not an in-memory way of doing the same thing
			//var root = HttpContext.Current.Server.MapPath("~/App_Data/");
			//var streamProvider = new MultipartFormDataStreamProvider(root);
			
			var streamProvider = new InMemoryMultipartFormDataStreamProvider();
			await request.Content.ReadAsMultipartAsync(streamProvider, clientDisconnected);

			var querySegments = request.RequestUri.ParseQueryString();

			List<string> args = new List<string>()
			{
				command
			};
			foreach (var key in querySegments.AllKeys)
			{
				var value = querySegments[key];
				args.Add($"-{key}={value}");
			}

			ArgsInfo argsInfo = ArgsInfo.Parse(args.ToArray(), true, _settings.Signer.KnownThumbprints);

			var dataToSignFile = streamProvider.Files.FirstOrDefault(f => f.Headers.ContentDisposition.Name == "data_file");

			byte[] dataToSign = null;
			if (dataToSignFile != null)
			{
				dataToSign = await dataToSignFile.ReadAsByteArrayAsync();
			}
			else
			{
				Log.Error("File to sign is not found.");
			}

			SignerInputParameters ret = new SignerInputParameters()
			{
				ArgsInfo = argsInfo,
				DataToSign = dataToSign
			};

			return ret;
		}
		
		#endregion
	}
}
