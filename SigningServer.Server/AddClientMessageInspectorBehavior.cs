using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;

namespace SigningServer.Server
{
    public class AddClientMessageInspectorBehavior : IEndpointBehavior
    {
        /// <inheritdoc />
        public void Validate(ServiceEndpoint endpoint)
        {
        }

        /// <inheritdoc />
        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters)
        {
        }

        /// <inheritdoc />
        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher)
        {
#if DEBUG
            endpointDispatcher.DispatchRuntime.MessageInspectors.Add(new ClientMessageInspector());
#endif
        }

        /// <inheritdoc />
        public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)
        {
        }
    }
}