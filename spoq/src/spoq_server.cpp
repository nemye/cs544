/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Demo client application for the Sensor Protocol Over QUIC (SPQO). See the
README.MD at the top level for build and run instructions.

    Built upon msquic "sample" application.

--*/

#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <string>

#include "msquic.h"
#include "quic_config.h"
#include "spoq.h"
#include "utils.h"

// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
const QUIC_REGISTRATION_CONFIG RegConfig = {"spoq_server",
                                            QUIC_EXECUTION_PROFILE_LOW_LATENCY};

// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
const QUIC_BUFFER Alpn = {sizeof("sample") - 1, (uint8_t*)"sample"};

// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
HQUIC Registration;

// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
HQUIC Configuration;

// The server SPOQ state
SPOQ_STATE state = SPOQ_STATE::INIT;

uint32_t MessageCount = 0;
constexpr uint32_t MAX_MESSAGE_COUNT = 100;

void PrintUsage() {
  std::cout << "\n"
               "quicsample runs a simple client or server.\n"
               "\n"
               "Usage:\n"
               "\n"
               "  quicsample.exe -server -cert_hash:<...>\n"
               "  quicsample.exe -server -cert_file:<...> -key_file:<...> "
               "[-password:<...>]\n";
}

// Allocates and sends some NDJSON data over a QUIC stream.
void ServerSend(_In_ HQUIC Stream) {
  setSpoqState(state, SPOQ_STATE::SENDING);
  while (MessageCount < MAX_MESSAGE_COUNT) {
    // Variable-size JSON: simulate size variation with random padding
    const int padding = rand() % 20;  // random 0–19 extra spaces

    // Allocate buffer: QUIC_BUFFER + payload
    void* SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + 64);
    if (SendBufferRaw == NULL) {
      std::cout
          << "SendBuffer allocation failed for message << MessageCount << !\n";
      MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      return;
    }

    QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);

    // Write variable length NDJSON message to the buffer
    int len = snprintf((char*)SendBuffer->Buffer, 64, "{\"msg\": %u}%*s\n",
                       MessageCount, padding, "x");
    SendBuffer->Length = (uint32_t)len;

    // Send the message, but only set QUIC_SEND_FLAG_FIN on the last one
    QUIC_SEND_FLAGS flags = (MessageCount == MessageCount - 1)
                                ? QUIC_SEND_FLAG_FIN
                                : QUIC_SEND_FLAG_NONE;

    QUIC_STATUS Status =
        MsQuic->StreamSend(Stream, SendBuffer, 1, flags, SendBufferRaw);
    // Note SendBufferRaw is freed in QUIC_STREAM_EVENT_SEND_COMPLETE case

    if (QUIC_FAILED(Status)) {
      std::cout << "[" << Stream << "] StreamSend failed at message "
                << MessageCount << ", " << Status << "!\n ";
      free(SendBufferRaw);
      setSpoqState(state, SPOQ_STATE::ERROR);
      MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      return;
    }

    ++MessageCount;
  }
}

// The server's callback for stream events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ServerStreamCallback(_In_ HQUIC Stream, _In_opt_ void* Context,
                         _Inout_ QUIC_STREAM_EVENT* Event) {
  UNREFERENCED_PARAMETER(Context);
  std::cout << "[" << Stream
            << "] Stream event: " << QuicStreamEventTypeToString(Event->Type)
            << "\n";
  switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE: {
      auto sendBuffer =
          static_cast<QUIC_BUFFER*>(Event->SEND_COMPLETE.ClientContext);
      if (sendBuffer) {
        std::string message(reinterpret_cast<const char*>(sendBuffer->Buffer),
                            sendBuffer->Length);
        std::cout << "[" << Stream << "] Stream event: Data sent: " << message;

        // Free the original sendBuffer memory
        free(sendBuffer);
      } else {
        std::cout << "[" << Stream << "] Stream event: Message send error!)\n";
      }
      break;
    }
    case QUIC_STREAM_EVENT_RECEIVE:
      // Data was received from the peer on the stream.
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      // The peer aborted its send direction of the stream.
      MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      setSpoqState(state, SPOQ_STATE::ERROR);
      break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      setSpoqState(state, SPOQ_STATE::WAITING);
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      MsQuic->StreamClose(Stream);
      setSpoqState(state, SPOQ_STATE::CLOSED);
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}

// The server's callback for connection events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ServerConnectionCallback(_In_ HQUIC Connection, _In_opt_ void* Context,
                             _Inout_ QUIC_CONNECTION_EVENT* Event) {
  UNREFERENCED_PARAMETER(Context);
  std::cout << "[" << Connection << "] Connection event: "
            << QuicConnectionEventTypeToString(Event->Type) << "\n";
  switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      // The handshake has completed for the connection.
      setSpoqState(state, SPOQ_STATE::ESTABLISHED);
      MsQuic->ConnectionSendResumptionTicket(
          Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.
      if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
          QUIC_STATUS_CONNECTION_IDLE) {
        std::cout << "[" << Connection
                  << "] Connection event: Successfully shut down on idle.\n";
        setSpoqState(state, SPOQ_STATE::CLOSED);
      } else {
        std::cout << "[" << Connection
                  << "] Connection event: Shut down by transport, 0x"
                  << std::hex << Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status
                  << std::dec << "\n";
        PrintQuicErrorCodeInfo(
            Event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode);
        setSpoqState(state, SPOQ_STATE::ERROR);
      }
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      // The connection was explicitly shut down by the peer.
      std::cout << "[" << Connection
                << "] Connection event: Shut down by peer, 0x" << std::hex
                << (unsigned long long)
                       Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode
                << std::dec << "\n";
      setSpoqState(state, SPOQ_STATE::ERROR);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
      MsQuic->ConnectionClose(Connection);
      setSpoqState(state, SPOQ_STATE::CLOSED);
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      // The peer has started/created a new stream. Begin sending data
      MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                                 (void*)ServerStreamCallback, NULL);
      ServerSend(Event->PEER_STREAM_STARTED.Stream);
      break;
    case QUIC_CONNECTION_EVENT_RESUMED:
      // The connection succeeded in doing a TLS resumption of a previous
      // connection's session.
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}

// The server's callback for listener events from MsQuic.
_IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API
    ServerListenerCallback(_In_ HQUIC Listener, _In_opt_ void* Context,
                           _Inout_ QUIC_LISTENER_EVENT* Event) {
  UNREFERENCED_PARAMETER(Listener);
  UNREFERENCED_PARAMETER(Context);
  QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
  switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
      // A new connection is being attempted by a client. For the handshake to
      // proceed, the server must provide a configuration for QUIC to use. The
      // app MUST set the callback handler before returning.
      MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection,
                                 (void*)ServerConnectionCallback, NULL);
      Status = MsQuic->ConnectionSetConfiguration(
          Event->NEW_CONNECTION.Connection, Configuration);
      break;
    default:
      break;
  }
  return Status;
}

// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
BOOLEAN
ServerLoadConfiguration(_In_ int argc,
                        _In_reads_(argc) _Null_terminated_ char* argv[]) {
  QUIC_SETTINGS Settings = {0};
  // Configures the server's idle timeout.
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;
  // Configures the server's resumption level to allow for resumption and
  // 0-RTT.
  Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
  Settings.IsSet.ServerResumptionLevel = TRUE;
  // Configures the server's settings to allow for the peer to open a single
  // bidirectional stream. By default connections are not configured to allow
  // any streams from the peer.
  Settings.PeerBidiStreamCount = 1;
  Settings.IsSet.PeerBidiStreamCount = TRUE;

  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES;

  const char* Cert;
  const char* KeyFile;
  const char* CaFile;
  if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
      (KeyFile = GetValue(argc, argv, "key_file")) != NULL &&
      (CaFile = GetValue(argc, argv, "ca_file")) != NULL) {
    Config.CertFile.CertificateFile = (char*)Cert;
    Config.CertFile.PrivateKeyFile = (char*)KeyFile;
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Config.CredConfig.CertificateFile = &Config.CertFile;
    Config.CredConfig.CaCertificateFile = (char*)CaFile;

    // Enforce validation of the client upon connection
    Config.CredConfig.Flags |=
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION;
    Config.CredConfig.Flags |=
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
    Config.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;

    std::cout << "Cert: " << Cert << "\n";
    std::cout << "Key : " << KeyFile << "\n";
    std::cout << "CA  : " << (CaFile ? CaFile : "none") << "\n";
  } else {
    std::cout << "Must specify ['cert_file', 'key_file', and 'ca_file']!\n";
    return FALSE;
  }

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    setSpoqState(state, SPOQ_STATE::ERROR);
    std::cout << "ConfigurationOpen failed, 0x" << std::hex << Status
              << std::dec << " !\n ";
    return FALSE;
  }

  // Loads the TLS credential part of the configuration.
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config.CredConfig))) {
    setSpoqState(state, SPOQ_STATE::ERROR);
    std::cout << "ConfigurationLoadCredential failed, 0x" << std::hex << Status
              << std::dec << "!\n";
    return FALSE;
  }

  return TRUE;
}

// Runs the server side of the protocol.
void RunServer(_In_ int argc, _In_reads_(argc) _Null_terminated_ char* argv[]) {
  QUIC_STATUS Status;
  HQUIC Listener = NULL;

  auto shutdown = [&]() {
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
  };

  // Configures the address used for the listener to listen on all IP
  // addresses and the given UDP port.
  QUIC_ADDR Address = {0};
  QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
  QuicAddrSetPort(&Address, UdpPort);

  // Load the server configuration based on the command line.
  if (!ServerLoadConfiguration(argc, argv)) {
    return;
  }

  // Create/allocate a new listener object.
  if (QUIC_FAILED(Status = MsQuic->ListenerOpen(
                      Registration, ServerListenerCallback, NULL, &Listener))) {
    setSpoqState(state, SPOQ_STATE::ERROR);
    std::cout << "ListenerOpen failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    shutdown();
  }

  // Starts listening for incoming connections.
  if (QUIC_FAILED(Status =
                      MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
    setSpoqState(state, SPOQ_STATE::ERROR);
    std::cout << "ListenerStart failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    shutdown();
  }

  // Continue listening for connections until the Enter key is pressed.
  std::cout << "Press Enter to exit.\n\n";
  setSpoqState(state, SPOQ_STATE::WAITING);
  std::cin.get();

  shutdown();
}

int QUIC_MAIN_EXPORT main(_In_ int argc,
                          _In_reads_(argc) _Null_terminated_ char* argv[]) {
  setSpoqState(state, SPOQ_STATE::INIT);
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

  auto shutdown = [&]() {
    if (MsQuic != NULL) {
      if (Configuration != NULL) {
        MsQuic->ConfigurationClose(Configuration);
      }
      if (Registration != NULL) {
        // This will block until all outstanding child objects have been
        // closed.
        MsQuic->RegistrationClose(Registration);
      }
      MsQuicClose(MsQuic);
      setSpoqState(state, SPOQ_STATE::CLOSED);
    }
  };

  // Open a handle to the library and get the API function table.
  if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
    setSpoqState(state, SPOQ_STATE::ERROR);
    std::cout << "MsQuicOpen2 failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    shutdown();
    return (int)Status;
  }

  // Create a registration for the app's connections.
  if (QUIC_FAILED(Status =
                      MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
    setSpoqState(state, SPOQ_STATE::ERROR);
    std::cout << "RegistrationOpen failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    shutdown();
    return (int)Status;
  }

  if (argc == 1 || GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
    PrintUsage();
  } else {
    RunServer(argc, argv);
  }

  shutdown();
  return (int)Status;
}
