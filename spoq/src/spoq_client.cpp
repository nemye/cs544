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

#include <iomanip>
#include <iostream>
#include <string>

#include "msquic.h"
#include "quic_config.h"
#include "utils.h"

// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
const QUIC_REGISTRATION_CONFIG RegConfig = {"spoq_client",
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

// The struct to be filled with TLS secrets
// for debugging packet captured with e.g. Wireshark.
QUIC_TLS_SECRETS ClientSecrets = {0};

// The name of the environment variable being
// used to get the path to the ssl key log file.
const char* SslKeyLogEnvVar = "SSLKEYLOGFILE";

void PrintUsage() {
  std::cout
      << "\n"
         "quicsample runs a simple client.\n"
         "\n"
         "Usage:\n"
         "\n"
         "  quicsample.exe -client -unsecure -target:{IPAddress|Hostname} "
         "[-ticket:<ticket>]\n";
}

// The clients's callback for stream events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ClientStreamCallback(_In_ HQUIC Stream, _In_opt_ void* Context,
                         _Inout_ QUIC_STREAM_EVENT* Event) {
  UNREFERENCED_PARAMETER(Context);

  std::cout << "[" << Stream
            << "] Stream event: " << QuicStreamEventTypeToString(Event->Type)
            << "\n";
  switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      free(Event->SEND_COMPLETE.ClientContext);
      break;
    case QUIC_STREAM_EVENT_RECEIVE: {
      // Data was received from the peer on the stream.
      std::string buffer;
      // Append incoming data to the string buffer
      for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
        buffer.append(
            reinterpret_cast<const char*>(Event->RECEIVE.Buffers[i].Buffer),
            Event->RECEIVE.Buffers[i].Length);
      }
      // Process full newline-delimited messages
      size_t pos = 0;
      while ((pos = buffer.find('\n')) != std::string::npos) {
        std::string message = buffer.substr(0, pos);
        buffer.erase(0, pos + 1);
        // Print size in bytes and the message
        std::cout << "[" << Stream << "] Stream event: Received message ("
                  << message.size() << " bytes): " << message << '\n';
      }
      break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      // The peer gracefully shut down its send direction of the stream.
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      // The peer aborted its send direction of the stream.
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
        MsQuic->StreamClose(Stream);
      }
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}

void ClientOpenStream(_In_ HQUIC Connection) {
  QUIC_STATUS Status;
  HQUIC Stream = NULL;

  // Create/allocate a new bidirectional stream. The stream is just allocated
  // and no QUIC stream identifier is assigned until it's started.
  if (QUIC_FAILED(
          Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE,
                                      ClientStreamCallback, NULL, &Stream))) {
    std::cout << "StreamOpen failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                               0);
  }

  // Starts the bidirectional stream. By default, the peer is not notified of
  // the stream being started until data is sent on the stream.
  if (QUIC_FAILED(Status = MsQuic->StreamStart(
                      Stream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
    std::cout << "StreamStart failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    MsQuic->StreamClose(Stream);
    MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                               0);
  }
}

// The clients's callback for connection events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ClientConnectionCallback(_In_ HQUIC Connection, _In_opt_ void* Context,
                             _Inout_ QUIC_CONNECTION_EVENT* Event) {
  UNREFERENCED_PARAMETER(Context);
  std::cout << "[" << Connection << "] Connection event: "
            << QuicConnectionEventTypeToString(Event->Type) << "\n";
  if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
    const char* SslKeyLogFile = getenv(SslKeyLogEnvVar);
    if (SslKeyLogFile != NULL) {
      WriteSslKeyLogFile(SslKeyLogFile, &ClientSecrets);
    }
  }

  switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      // The handshake has completed for the connection.
      ClientOpenStream(Connection);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.
      if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
          QUIC_STATUS_CONNECTION_IDLE) {
        std::cout << "[" << Connection
                  << "] Connection event: Successfully shut down on idle.\n";
      } else {
        std::cout << "[" << Connection
                  << "] Connection event: Shut down by transport, 0x"
                  << std::hex << Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status
                  << std::dec << "\n";
      }
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      // The connection was explicitly shut down by the peer.
      std::cout << "[" << Connection
                << "] Connection event: Shut down by peer, 0x" << std::hex
                << (unsigned long long)
                       Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode
                << std::dec << "\n";
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
      if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
        MsQuic->ConnectionClose(Connection);
      }
      break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
      // A resumption ticket (also called New Session Ticket or NST) was
      // received from the server.
      std::cout << "[" << Connection
                << "] Connection event: Resumption ticket received ("
                << Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength
                << " bytes):\n";
      for (uint32_t i = 0;
           i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(
                         Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]) << std::dec;
      }
      std::cout << "\n";
      break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
      std::cout << "[" << Connection
                << "] Connection event: Ideal Processor is:"
                << Event->IDEAL_PROCESSOR_CHANGED.IdealProcessor
                << ", Partition Index "
                << Event->IDEAL_PROCESSOR_CHANGED.PartitionIndex << "\n";
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}

// Helper function to load a client configuration.
BOOLEAN
ClientLoadConfiguration(BOOLEAN Unsecure) {
  QUIC_SETTINGS Settings = {0};
  // Configures the client's idle timeout.
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;

  // Configures a default client configuration, optionally disabling
  // server certificate validation.
  QUIC_CREDENTIAL_CONFIG CredConfig;
  memset(&CredConfig, 0, sizeof(CredConfig));
  CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
  CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
  if (Unsecure) {
    CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
  }

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    std::cout << "ConfigurationOpen failed, 0x" << std::hex << Status
              << std::dec << " !\n ";
    return FALSE;
  }

  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration,
                                                               &CredConfig))) {
    std::cout << "ConfigurationLoadCredential failed, 0x" << std::hex << Status
              << std::dec << "!\n";
    return FALSE;
  }

  return TRUE;
}

// Runs the client side of the protocol.
void RunClient(_In_ int argc, _In_reads_(argc) _Null_terminated_ char* argv[]) {
  // Load the client configuration based on the "unsecure" command line option.
  if (!ClientLoadConfiguration(GetFlag(argc, argv, "unsecure"))) {
    return;
  }

  QUIC_STATUS Status;
  const char* ResumptionTicketString = NULL;
  const char* SslKeyLogFile = getenv(SslKeyLogEnvVar);
  HQUIC Connection = NULL;

  auto shutdown = [&]() {
    if (QUIC_FAILED(Status) && Connection != NULL) {
      MsQuic->ConnectionClose(Connection);
    }
  };

  // Allocate a new connection object.
  if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration,
                                                  ClientConnectionCallback,
                                                  NULL, &Connection))) {
    std::cout << "ConnectionOpen failed, 0x" << std::hex << Status << std::dec
              << "!\n";
  }

  if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != NULL) {
    // If provided at the command line, set the resumption ticket that can
    // be used to resume a previous session.
    uint8_t ResumptionTicket[10240];
    uint16_t TicketLength = (uint16_t)DecodeHexBuffer(
        ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket);
    if (QUIC_FAILED(Status = MsQuic->SetParam(
                        Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET,
                        TicketLength, ResumptionTicket))) {
      std::cout << "SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x"
                << std::hex << Status << std::dec << "!\n";
      shutdown();
    }
  }

  if (SslKeyLogFile != NULL) {
    if (QUIC_FAILED(
            Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_TLS_SECRETS,
                                      sizeof(ClientSecrets), &ClientSecrets))) {
      std::cout << "SetParam(QUIC_PARAM_CONN_TLS_SECRETS) failed, 0x"
                << std::hex << Status << std::dec << "!\n";
      shutdown();
    }
  }

  // Get the target / server name or IP from the command line.
  const char* Target;
  if ((Target = GetValue(argc, argv, "target")) == NULL) {
    std::cout << "Must specify '-target' argument!\n";
    Status = QUIC_STATUS_INVALID_PARAMETER;
    shutdown();
  }

  // Start the connection to the server.
  if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration,
                                                   QUIC_ADDRESS_FAMILY_UNSPEC,
                                                   Target, UdpPort))) {
    std::cout << "ConnectionStart failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    shutdown();
  }

  shutdown();
}

int QUIC_MAIN_EXPORT main(_In_ int argc,
                          _In_reads_(argc) _Null_terminated_ char* argv[]) {
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
    }
  };

  // Open a handle to the library and get the API function table.
  if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
    std::cout << "MsQuicOpen2 failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    shutdown();
    return (int)Status;
  }

  // Create a registration for the app's connections.
  if (QUIC_FAILED(Status =
                      MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
    std::cout << "RegistrationOpen failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    shutdown();
    return (int)Status;
  }

  if (argc == 1 || GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
    PrintUsage();
  } else {
    RunClient(argc, argv);
  }

  shutdown();
  return (int)Status;
}
