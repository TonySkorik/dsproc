using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using UniDsproc.Configuration;

namespace UniDsproc.Api.Controllers.V1
{
	[RoutePrefix("api/v1/service")]
	public class ServiceController : ApiController
	{
		private readonly AppSettings _settings;

		public ServiceController(AppSettings settings)
		{
			_settings = settings;
		}

		[HttpGet]
		[Route("version")]
		public IHttpActionResult Version()
		{
			return Ok(Program.Version);
		}
	}
}
