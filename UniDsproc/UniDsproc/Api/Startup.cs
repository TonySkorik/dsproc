﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using Autofac;
using Autofac.Integration.WebApi;
using Owin;
using Space.Core;
using Space.Core.Interfaces;
using Space.Core.Processor;
using Space.Core.Serializer;
using Space.Core.Verifier;
using UniDsproc.Configuration;

namespace UniDsproc.Api
{
	public class Startup
	{
		private readonly AppSettings _settings;

		public Startup(AppSettings settings)
		{
			_settings = settings;
		}

		public void Configure(IAppBuilder appBuilder)
		{
			// Configure Web API for self-host. 
			HttpConfiguration config = new HttpConfiguration();

			var autofacContainer = BuildContainer(config);
			config.DependencyResolver = new AutofacWebApiDependencyResolver(autofacContainer);

			config.MapHttpAttributeRoutes();

			// remove xml formatter
			config.Formatters.Remove(config.Formatters.XmlFormatter);
			
			appBuilder.UseWebApi(config);
			
			config.EnsureInitialized();
		}

		private ILifetimeScope BuildContainer(HttpConfiguration httpCOnfiguration)
		{
			var builder = new ContainerBuilder();

			builder.RegisterApiControllers(Assembly.GetExecutingAssembly());
			builder.RegisterWebApiFilterProvider(httpCOnfiguration);
			builder.RegisterWebApiModelBinderProvider();

			builder.RegisterInstance(_settings).AsSelf().SingleInstance();
			builder.RegisterType<Signer>().As<ISigner>().SingleInstance();
			builder.RegisterType<SignatureVerifier>().As<ISignatureVerifier>().SingleInstance();
			builder.RegisterType<CertificateUtils>().As<ICertificateProcessor>().SingleInstance();
			builder.RegisterType<CertificateSerializer>().As<ICertificateSerializer>().SingleInstance();

			var container = builder.Build();

			return container;
		}
	}
}
