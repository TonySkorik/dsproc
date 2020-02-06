using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using Owin;

namespace UniDsproc.Api
{
	public class Startup
	{
		public void Configuration(IAppBuilder appBuilder)
		{
			// Configure Web API for self-host. 
			HttpConfiguration config = new HttpConfiguration();
			config.MapHttpAttributeRoutes();

			// remove xml formatter
			config.Formatters.Remove(config.Formatters.XmlFormatter);

			//config.Routes.MapHttpRoute(
			//	name: "DefaultApi",
			//	routeTemplate: "api/{controller}/{id}",
			//	defaults: new { id = RouteParameter.Optional }
			//);
			
			appBuilder.UseWebApi(config);

			config.EnsureInitialized();
		}
	}
}
