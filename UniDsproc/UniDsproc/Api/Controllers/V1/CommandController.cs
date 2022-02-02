using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using Newtonsoft.Json;
using Serilog;
using Space.Core.Interfaces;
using UniDsproc.Api.Constants;
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
		private readonly ISignatureVerifier _verifier;
		private readonly ICertificateProcessor _certificateProcessor;
		private readonly ICertificateSerializer _certificateSerializer;

		public CommandController(
			AppSettings settings,
			ISigner signer,
			ISignatureVerifier verifier,
			ICertificateProcessor certificateProcessor,
			ICertificateSerializer certificateSerializer)
		{
			_settings = settings;
			_signer = signer;
			_verifier = verifier;
			_certificateProcessor = certificateProcessor;
			_certificateSerializer = certificateSerializer;
		}

		[HttpPost]
		[Route(("{command}"))]
		public async Task<IHttpActionResult> Command(string command)
		{
			if (!Request.IsAuthorized())
			{
				Log.Fatal("Blocked WebApiHost request from {blockedIp}", Request.GetRemoteIp());
				return StatusCode(HttpStatusCode.Forbidden);
			}

			var context = new OperationContext(Request);

			try
			{
				Program.WebApiHost.ClientConnected();
				context.SetRawInputParameters(Request.RequestUri.Query, command);

				var inputParameters = await ReadInputParameters(Request, command);

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

						var returnMessage = new HttpResponseMessage(HttpStatusCode.OK)
						{
							Content = new StreamContent(streamToReturn),
						};

						SetAdditionalResponseProperties(returnMessage);

						Log.Debug(
							"Successfully signed file from ip {requesterIp} with following parameters: [{parameters}]",
							Request.GetRemoteIp(),
							context.RawInputParameters);

						return SuccessResult(returnMessage, context);

					case ProgramFunction.Verify:
						var verifierResponse = _verifier.VerifySignature(
							inputParameters.ArgsInfo.SigType,
							nodeId: inputParameters.ArgsInfo.NodeId,
							signedFileBytes: inputParameters.DataToSign,
							signatureFileBytes: inputParameters.SignatureFileBytes,
							isVerifyCertificateChain: inputParameters.ArgsInfo.IsVerifyCertificateChain);

						var verifierRetrurnMessge = new HttpResponseMessage(HttpStatusCode.OK)
						{
							Content = new StringContent(JsonConvert.SerializeObject(verifierResponse))
						};

						SetAdditionalResponseProperties(verifierRetrurnMessge);

						Log.Debug(
							"Successfully checked signature from ip {requesterIp} with following parameters: [{parameters}]",
							Request.GetRemoteIp(),
							context.RawInputParameters);

						return SuccessResult(verifierRetrurnMessge, context);

					case ProgramFunction.Extract:
						var readCertificate = _certificateProcessor.ReadCertificateFromSignedFile(
							inputParameters.ArgsInfo.SigType,
							signedFileBytes: inputParameters.DataToSign,
							signatureFileBytes: inputParameters.SignatureFileBytes,
							nodeId: inputParameters.ArgsInfo.NodeId);

						var serializableCertificate = _certificateSerializer.CertificateToSerializable(readCertificate);

						var extractedCertificateRetrurnMessge = new HttpResponseMessage(HttpStatusCode.OK)
						{
							Content = new StringContent(JsonConvert.SerializeObject(serializableCertificate))
						};

						SetAdditionalResponseProperties(extractedCertificateRetrurnMessge);

						Log.Debug(
							"Successfully extracted certificate from signed file from ip {requesterIp} with following parameters: [{parameters}]",
							Request.GetRemoteIp(),
							context.RawInputParameters);

						return SuccessResult(extractedCertificateRetrurnMessge, context);

					case ProgramFunction.VerifyAndExtract:
						var verifierResponsePart = _verifier.VerifySignature(
							inputParameters.ArgsInfo.SigType,
							signedFileBytes: inputParameters.DataToSign,
							signatureFileBytes: inputParameters.SignatureFileBytes,
							nodeId: inputParameters.ArgsInfo.NodeId,
							isVerifyCertificateChain: inputParameters.ArgsInfo.IsVerifyCertificateChain);

						var readCertificatePart = _certificateProcessor.ReadCertificateFromSignedFile(
							inputParameters.ArgsInfo.SigType,
							signedFileBytes: inputParameters.DataToSign,
							signatureFileBytes: inputParameters.SignatureFileBytes,
							nodeId: inputParameters.ArgsInfo.NodeId);

						var serializableCertificatePart =
							_certificateSerializer.CertificateToSerializable(readCertificatePart);

						var combinedResponse = new CombinedResponse()
						{
							VerificationResult = verifierResponsePart,
							ExtractedCertificate = serializableCertificatePart
						};

						if (verifierResponsePart.SigningDateTime.HasValue)
						{
							combinedResponse.CertificateInfo = new()
							{
								SigningDateTime = verifierResponsePart.SigningDateTime
							};
						}

						var verifyAndExtractRetrurnMessge = new HttpResponseMessage(HttpStatusCode.OK)
						{
							Content = new StringContent(JsonConvert.SerializeObject(combinedResponse))
						};

						SetAdditionalResponseProperties(verifyAndExtractRetrurnMessge);

						Log.Debug(
							"Successfully verified and extracted certificate from signed file from ip {requesterIp} with following parameters: [{parameters}]",
							Request.GetRemoteIp(),
							context.RawInputParameters);

						return SuccessResult(verifyAndExtractRetrurnMessge, context);

					case ProgramFunction.Describe:
						var readInputCertificate = _certificateProcessor.ReadCertificateFromCertificateFile(inputParameters.CertificateFileBytes);

						var describedCertificate =
							_certificateSerializer.CertificateToSerializable(readInputCertificate);

						var certificateDescribeReturnMessge = new HttpResponseMessage(HttpStatusCode.OK)
						{
							Content = new StringContent(JsonConvert.SerializeObject(describedCertificate))
						};

						Log.Debug(
							"Successfully described extracted certificate from ip {requesterIp}",
							Request.GetRemoteIp());

						return SuccessResult(certificateDescribeReturnMessge, context);
					default:
						return ErrorResultBadRequest($"Command {command} is not supported.", context);
				}
			}
			catch (OperationCanceledException opce)
			{
				Log.Warning("Client disconnected prior to singing completion");
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

		private void SetAdditionalResponseProperties(HttpResponseMessage returnMessage)
		{
			returnMessage.Content.Headers.ContentType =
				new MediaTypeHeaderValue("application/octet-stream");
			returnMessage.Headers.Add("UniApp", "UnDsProc");
			returnMessage.Headers.Add("UniVersion", Program.Version);
		}

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
			string path =
				$"data\\{now.Year:D4}\\{now.Month:D2}\\{now.Day:D2}\\{now.Hour:D2}-{now.Minute:D2}-{now.Second:D2}_{now.Millisecond:D3}";
			Directory.CreateDirectory(path);

			var clientIpAddress = context.Request.GetRemoteIp();

			string requestParametersFileName = Path.Combine(path, "parameters.txt");
			string inputDataFileName = Path.Combine(path, "input.bin");
			string outputDataFileName = Path.Combine(path, $"output.{context.ReturnedStatusCode}");
			string ipDataFile = Path.Combine(path, $"{clientIpAddress}.ip");

			File.WriteAllText(requestParametersFileName, context.RawInputParameters);
			File.WriteAllBytes(inputDataFileName, context.InputParameters?.DataToSign ?? new byte[0]);
			File.WriteAllText(outputDataFileName, context.SignerResponse?.SignedData ?? context.ExceptionMessage);
			File.WriteAllText(ipDataFile, clientIpAddress);
		}

		private (bool isParametersOk, string errorReason) ValidateParameters(ApiInputParameters parameters)
		{
			if (parameters.ArgsInfo.Function != ProgramFunction.Describe && parameters.DataToSign == null)
			{
				return (false, "No data to sign.");
			}

			if (parameters.ArgsInfo.Function == ProgramFunction.Describe && parameters.CertificateFileBytes == null)
			{
				return (false, "No certificate to describe.");
			}

			return (true, string.Empty);
		}

		private async Task<ApiInputParameters> ReadInputParameters(HttpRequestMessage request, string command)
		{
			var clientDisconnectedCancellationToken =
				request.GetOwinContext()?.Request?.CallCancelled ?? CancellationToken.None;

			//NOTE: this is not an in-memory way of doing the same thing
			//var root = HttpContext.Current.Server.MapPath("~/App_Data/");
			//var streamProvider = new MultipartFormDataStreamProvider(root);

			var streamProvider = new InMemoryMultipartFormDataStreamProvider();
			await request.Content.ReadAsMultipartAsync(streamProvider, clientDisconnectedCancellationToken);

			var querySegments = request.RequestUri.ParseQueryString();

			List<string> args = new()
			{
				command
			};

			foreach (var key in querySegments.AllKeys)
			{
				var value = querySegments[key];
				args.Add($"-{key}={value}");
			}

			ArgsInfo argsInfo = ArgsInfo.Parse(args.ToArray(), true, _settings.Signer.KnownThumbprints);

			var dataToSign = await ReadInputFile(streamProvider, ApiInputFileContants.DataToSignFileFormFieldName);

			if (dataToSign == null
				&& argsInfo.Function != ProgramFunction.Describe)
			{
				Log.Error("File to sign is not found");
			}

			var signatureBytes = await ReadInputFile(streamProvider, ApiInputFileContants.SignatureFileFormFieldName);

			var certificateBytes = await ReadInputFile(
				streamProvider,
				ApiInputFileContants.CertificateFileFormFieldName);

			ApiInputParameters ret = new()
			{
				ArgsInfo = argsInfo,
				DataToSign = dataToSign,
				SignatureFileBytes = signatureBytes,
				CertificateFileBytes = certificateBytes
			};

			return ret;
		}

		private async Task<byte[]> ReadInputFile(InMemoryMultipartFormDataStreamProvider streamProvider, string fileName)
		{
			var formFile =
				streamProvider.Files.FirstOrDefault(f => f.Headers.ContentDisposition.Name == fileName);

			byte[] fileBytes = null;
			if (formFile != null)
			{
				fileBytes = await formFile.ReadAsByteArrayAsync();
			}

			return fileBytes;
		}

		#endregion
	}
}
