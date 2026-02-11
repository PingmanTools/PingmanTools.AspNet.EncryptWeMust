using System;

namespace PingmanTools.AspNet.EncryptWeMust.Exceptions
{
	class OrderInvalidException : Exception
	{
		public OrderInvalidException()
		{
		}

		public OrderInvalidException(string message) : base(message)
		{
		}

		public OrderInvalidException(string message, Exception innerException) : base(message, innerException)
		{
		}
	}
}
