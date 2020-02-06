using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using Microsoft.Owin.Hosting;

namespace UniDsproc.Api
{
	public class WebApiHost : INotifyPropertyChanged
	{
		#region NotifyPropertyChanged

		public event PropertyChangedEventHandler PropertyChanged;

		protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		#endregion

		#region Private

		private static readonly object SyncRoot = new object();
		private IDisposable _apiServer;
		private readonly HashSet<string> _allowedIpAddresses;

		#endregion

		#region Props

		public string Protocol { get; }
		public int Port { get; }

		private int _connectedClientsCount;
		public int ConnectedClientsCount
		{
			get => _connectedClientsCount;
			set
			{
				_connectedClientsCount = value;
				OnPropertyChanged();
			}
		}

		private bool _isActive;
		public bool IsActive
		{
			set
			{
				_isActive = value;
				OnPropertyChanged();
			}
			get => _isActive;
		}

		#endregion

		public WebApiHost(string protocol, int port, HashSet<string> allowedIpAddresses)
		{
			Protocol = protocol;
			Port = port;
			_allowedIpAddresses = allowedIpAddresses;
			InitLogger();
		}

		#region Initialization methods

		private void InitLogger()
		{

		}

		#endregion

		#region Counters methods

		public void ClientConnected()
		{
			lock (SyncRoot)
			{
				ConnectedClientsCount++;
			}
		}

		public void ClientDisconnected()
		{
			lock (SyncRoot)
			{
				ConnectedClientsCount--;
			}
		}

		#endregion

		#region Methods to start / stop server

		public void Start()
		{
			IsActive = true;
			string baseAddress = $"{Protocol}://*:{Port}/";
			_apiServer = WebApp.Start<Startup>(baseAddress);
			
		}

		public void Stop()
		{
			if (_apiServer != null)
			{
				_apiServer.Dispose();
				_apiServer = null;
				IsActive = false;
			}
		}

		#endregion

		#region Security methods

		public bool IsIpAllowedToConnect(string ipAddress)
			=> !_allowedIpAddresses.Any() || _allowedIpAddresses.Contains(ipAddress);

		#endregion
	}
}
