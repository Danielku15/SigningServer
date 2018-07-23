using System;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;
using NLog;

namespace SigningServer.Server
{
    public class ClientMessageInspector : IDispatchMessageInspector
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();
        public object AfterReceiveRequest(ref Message request, IClientChannel channel, InstanceContext instanceContext)
        {
            var remoteIp = GetRemoteIp(request);
            Log.Trace($"[{remoteIp}] Client requesting call {GetActionName()}");
            return remoteIp;
        }

        /// <inheritdoc />
        public void BeforeSendReply(ref Message reply, object correlationState)
        {
            Log.Trace($"[{correlationState}] Client call {GetActionName()} finished");
        }

        private string GetActionName()
        {
            try
            {
                var action = OperationContext.Current?.IncomingMessageHeaders.Action;
                if (action != null)
                {
                    return action.Replace("http://tempuri.org/", "");
                }
                return "UnknownAction";
            }
            catch (Exception e)
            {
                Log.Error(e, "Could not load action name");
                return "UnknownAction";
            }
        }

        private string GetRemoteIp(Message message)
        {
            try
            {
                var endpoint = message.Properties[RemoteEndpointMessageProperty.Name] as RemoteEndpointMessageProperty;
                if (endpoint != null)
                {
                    return $"{endpoint.Address}:{endpoint.Port}";
                }
                return "Unknown";
            }
            catch (Exception e)
            {
                Log.Error(e, "Could not load remote IP");
                return "Unknown";
            }
        }
    }
}