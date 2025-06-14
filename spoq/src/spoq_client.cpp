/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Demo client application for the Sensor Protocol Over QUIC (SPOQ). See the
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
#include "spoq.h"
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

// The client SPOQ state
SPOQ_STATE state = SPOQ_STATE::UNKNOWN;

// The name of the environment variable being
// used to get the path to the ssl key log file.
const char* SslKeyLogEnvVar = "SSLKEYLOGFILE";

void PrintUsage() {
  std::cout << "\n"
               "spoq_client runs a simple SPOQ client.\n"
               "\n"
               "Usage:\n"
               "\n"
               " spoq_server -cert_file:<...> -key_file:<...> -ca_file:<...> -target:{IPAddress|Hostname}\n";
}

// Send the response to the server
void SendNegotiate(_In_ HQUIC Stream, const bool success) {
  // Allocate buffer: QUIC_BUFFER + payload
  void* SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + 64);
  if (SendBufferRaw == NULL) {
    std::cout << "SendBuffer allocation failed for client negotiation!\n";
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    return;
  }

  QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
  SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);

  // Write a sample version negotitation message
  std::string success_str = success ? "0" : "1";
  std::string neg_msg =
      "{\"header\":{\"sensor_id\":\"1\",\"version\":\"1\",\"status\":\"" +
      success_str + "\"}}";
  int len = snprintf((char*)SendBuffer->Buffer, 64, "%s\n", neg_msg.c_str());
  SendBuffer->Length = (uint32_t)len;

  QUIC_SEND_FLAGS flags = QUIC_SEND_FLAG_START;

  QUIC_STATUS Status =
      MsQuic->StreamSend(Stream, SendBuffer, 1, flags, SendBufferRaw);
  // Note SendBufferRaw is freed in QUIC_STREAM_EVENT_SEND_COMPLETE case

  if (QUIC_FAILED(Status)) {
    std::cout << "[" << Stream
              << "] StreamSend failed to send negotation message - " << Status
              << "!\n ";
    free(SendBufferRaw);
    setSpoqState(state, SPOQ_STATE::ERROR);
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    return;
  }
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

      if (state == SPOQ_STATE::NEGOTIATE) {
        // lazy parsing of the message to negotiate
        // should integrate a proper json parsing library
        size_t pos = 0;
        std::string vstr = "\"version\":\"";
        bool success = false;
        if ((pos = buffer.find(vstr)) != std::string::npos) {
          std::string version = buffer.substr(pos + vstr.length(), 1);
          std::cout << "[" << Stream
                    << "] Negotiation event: version = " << version << "\n";
          success = (version == "1");
          if (success) {
            std::cout << "[" << Stream << "] Negotiation event: SUCCESS!\n";
            setSpoqState(state, SPOQ_STATE::ESTABLISHED);
          } else {
            std::cout << "[" << Stream << "] Negotiation event: FAILED!\n";
            setSpoqState(state, SPOQ_STATE::ERROR);
          }
        }
        SendNegotiate(Stream, success);
      } else {
        setSpoqState(state, SPOQ_STATE::RECEIVING);

        // Process full newline-delimited messages
        size_t pos = 0;
        while ((pos = buffer.find('\n')) != std::string::npos) {
          std::string message = buffer.substr(0, pos);
          buffer.erase(0, pos + 1);
          // Print size in bytes and the message
          std::cout << "[" << Stream << "] Stream event: Received message ("
                    << message.size() << " bytes): " << message << '\n';
        }
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
    setSpoqState(state, SPOQ_STATE::ERROR);
    MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                               0);
  }

  // Starts the bidirectional stream. By default, the peer is not notified of
  // the stream being started until data is sent on the stream.
  if (QUIC_FAILED(Status = MsQuic->StreamStart(
                      Stream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
    std::cout << "StreamStart failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    setSpoqState(state, SPOQ_STATE::ERROR);
    MsQuic->StreamClose(Stream);
    MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                               0);
  }

  setSpoqState(state, SPOQ_STATE::NEGOTIATE);
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
                         Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i])
                  << std::dec;
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
ClientLoadConfiguration(_In_ int argc,
                        _In_reads_(argc) _Null_terminated_ char* argv[]) {
  QUIC_SETTINGS Settings = {0};
  // Configures the client's idle timeout.
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;

  // Configures a default client configuration
  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;

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

    Config.CredConfig.Flags |=
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
    Config.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;

    std::cout << "Cert: " << Cert << "\n";
    std::cout << "Key : " << KeyFile << "\n";
    std::cout << "CA  : " << (CaFile ? CaFile : "none") << "\n";
  } else {
    std::cout << "Must specify ['cert_file' and 'key_file' (and "
                 "optionally 'password')]!\n";
    return FALSE;
  }

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    std::cout << "ConfigurationOpen failed, 0x" << std::hex << Status
              << std::dec << " !\n ";
    setSpoqState(state, SPOQ_STATE::ERROR);
    return FALSE;
  }

  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config.CredConfig))) {
    std::cout << "ConfigurationLoadCredential failed, 0x" << std::hex << Status
              << std::dec << "!\n";
    setSpoqState(state, SPOQ_STATE::ERROR);
    return FALSE;
  }

  return TRUE;
}

// Runs the client side of the protocol.
void RunClient(_In_ int argc, _In_reads_(argc) _Null_terminated_ char* argv[]) {
  // Load the client configuration
  if (!ClientLoadConfiguration(argc, argv)) {
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
    setSpoqState(state, SPOQ_STATE::ERROR);
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
      setSpoqState(state, SPOQ_STATE::ERROR);
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
    setSpoqState(state, SPOQ_STATE::ERROR);
    shutdown();
  }

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
        setSpoqState(state, SPOQ_STATE::CLOSED);
      }
      MsQuicClose(MsQuic);
    }
  };

  // Open a handle to the library and get the API function table.
  if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
    std::cout << "MsQuicOpen2 failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    setSpoqState(state, SPOQ_STATE::ERROR);
    shutdown();
    return (int)Status;
  }

  // Create a registration for the app's connections.
  if (QUIC_FAILED(Status =
                      MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
    std::cout << "RegistrationOpen failed, 0x" << std::hex << Status << std::dec
              << "!\n";
    setSpoqState(state, SPOQ_STATE::ERROR);
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
