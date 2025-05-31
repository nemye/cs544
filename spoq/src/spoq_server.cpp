/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Demo client application for the Sensor Protocol Over QUIC (SPQO). See the README.MD
    at the top level for build and run instructions.
    
    Built upon msquic "sample" application.

--*/

#include <stdio.h>
#include <stdlib.h>

#include "msquic.h"
#include "utils.h"
#include "quic_config.h"

//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
const QUIC_REGISTRATION_CONFIG RegConfig = {"spoq_server",
                                            QUIC_EXECUTION_PROFILE_LOW_LATENCY};

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
const QUIC_BUFFER Alpn = {sizeof("sample") - 1, (uint8_t*)"sample"};

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
HQUIC Registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
HQUIC Configuration;

void PrintUsage() {
  printf(
      "\n"
      "quicsample runs a simple client or server.\n"
      "\n"
      "Usage:\n"
      "\n"
      "  quicsample.exe -server -cert_hash:<...>\n"
      "  quicsample.exe -server -cert_file:<...> -key_file:<...> "
      "[-password:<...>]\n");
}

//
// Allocates and sends some data over a QUIC stream.
//
void ServerSend(_In_ HQUIC Stream) {
  //
  // Allocates and builds the buffer to send over the stream.
  //
  void* SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + SendBufferLength);
  if (SendBufferRaw == NULL) {
    printf("SendBuffer allocation failed!\n");
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    return;
  }
  QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
  SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
  SendBuffer->Length = SendBufferLength;

  printf("[strm][%p] Sending data...\n", Stream);

  //
  // Sends the buffer over the stream. Note the FIN flag is passed along with
  // the buffer. This indicates this is the last buffer on the stream and the
  // the stream is shut down (in the send direction) immediately after.
  //
  QUIC_STATUS Status;
  if (QUIC_FAILED(Status = MsQuic->StreamSend(
                      Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
    printf("StreamSend failed, 0x%x!\n", Status);
    free(SendBufferRaw);
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
  }
}

//
// The server's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ServerStreamCallback(_In_ HQUIC Stream, _In_opt_ void* Context,
                         _Inout_ QUIC_STREAM_EVENT* Event) {
  UNREFERENCED_PARAMETER(Context);
  switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      free(Event->SEND_COMPLETE.ClientContext);
      printf("[strm][%p] Data sent\n", Stream);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      //
      // Data was received from the peer on the stream.
      //
      printf("[strm][%p] Data received\n", Stream);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      //
      // The peer gracefully shut down its send direction of the stream.
      //
      printf("[strm][%p] Peer shut down\n", Stream);
      ServerSend(Stream);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      //
      // The peer aborted its send direction of the stream.
      //
      printf("[strm][%p] Peer aborted\n", Stream);
      MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      //
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      //
      printf("[strm][%p] All done\n", Stream);
      MsQuic->StreamClose(Stream);
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ServerConnectionCallback(_In_ HQUIC Connection, _In_opt_ void* Context,
                             _Inout_ QUIC_CONNECTION_EVENT* Event) {
  UNREFERENCED_PARAMETER(Context);
  switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      //
      // The handshake has completed for the connection.
      //
      printf("[conn][%p] Connected\n", Connection);
      MsQuic->ConnectionSendResumptionTicket(
          Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      //
      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.
      //
      if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
          QUIC_STATUS_CONNECTION_IDLE) {
        printf("[conn][%p] Successfully shut down on idle.\n", Connection);
      } else {
        printf("[conn][%p] Shut down by transport, 0x%x\n", Connection,
               Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
      }
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      //
      // The connection was explicitly shut down by the peer.
      //
      printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection,
             (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      //
      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
      //
      printf("[conn][%p] All done\n", Connection);
      MsQuic->ConnectionClose(Connection);
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      //
      // The peer has started/created a new stream. The app MUST set the
      // callback handler before returning.
      //
      printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
      MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                                 (void*)ServerStreamCallback, NULL);
      break;
    case QUIC_CONNECTION_EVENT_RESUMED:
      //
      // The connection succeeded in doing a TLS resumption of a previous
      // connection's session.
      //
      printf("[conn][%p] Connection resumed!\n", Connection);
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for listener events from MsQuic.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API
    ServerListenerCallback(_In_ HQUIC Listener, _In_opt_ void* Context,
                           _Inout_ QUIC_LISTENER_EVENT* Event) {
  UNREFERENCED_PARAMETER(Listener);
  UNREFERENCED_PARAMETER(Context);
  QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
  switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
      //
      // A new connection is being attempted by a client. For the handshake to
      // proceed, the server must provide a configuration for QUIC to use. The
      // app MUST set the callback handler before returning.
      //
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

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
  QUIC_CREDENTIAL_CONFIG CredConfig;
  union {
    QUIC_CERTIFICATE_HASH CertHash;
    QUIC_CERTIFICATE_HASH_STORE CertHashStore;
    QUIC_CERTIFICATE_FILE CertFile;
    QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
  };
} QUIC_CREDENTIAL_CONFIG_HELPER;

//
// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
//
BOOLEAN
ServerLoadConfiguration(_In_ int argc,
                        _In_reads_(argc) _Null_terminated_ char* argv[]) {
  QUIC_SETTINGS Settings = {0};
  //
  // Configures the server's idle timeout.
  //
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;
  //
  // Configures the server's resumption level to allow for resumption and
  // 0-RTT.
  //
  Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
  Settings.IsSet.ServerResumptionLevel = TRUE;
  //
  // Configures the server's settings to allow for the peer to open a single
  // bidirectional stream. By default connections are not configured to allow
  // any streams from the peer.
  //
  Settings.PeerBidiStreamCount = 1;
  Settings.IsSet.PeerBidiStreamCount = TRUE;

  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

  const char* Cert;
  const char* KeyFile;
  if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
    //
    // Load the server's certificate from the default certificate store,
    // using the provided certificate hash.
    //
    uint32_t CertHashLen = DecodeHexBuffer(
        Cert, sizeof(Config.CertHash.ShaHash), Config.CertHash.ShaHash);
    if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
      return FALSE;
    }
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
    Config.CredConfig.CertificateHash = &Config.CertHash;

  } else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
             (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {
    //
    // Loads the server's certificate from the file.
    //
    const char* Password = GetValue(argc, argv, "password");
    if (Password != NULL) {
      Config.CertFileProtected.CertificateFile = (char*)Cert;
      Config.CertFileProtected.PrivateKeyFile = (char*)KeyFile;
      Config.CertFileProtected.PrivateKeyPassword = (char*)Password;
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
      Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
    } else {
      Config.CertFile.CertificateFile = (char*)Cert;
      Config.CertFile.PrivateKeyFile = (char*)KeyFile;
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
      Config.CredConfig.CertificateFile = &Config.CertFile;
    }

  } else {
    printf(
        "Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and "
        "optionally 'password')]!\n");
    return FALSE;
  }

  //
  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  //
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    printf("ConfigurationOpen failed, 0x%x!\n", Status);
    return FALSE;
  }

  //
  // Loads the TLS credential part of the configuration.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config.CredConfig))) {
    printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
    return FALSE;
  }

  return TRUE;
}

//
// Runs the server side of the protocol.
//
void RunServer(_In_ int argc, _In_reads_(argc) _Null_terminated_ char* argv[]) {
  QUIC_STATUS Status;
  HQUIC Listener = NULL;

  auto shutdown = [&]() {
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
  };

  //
  // Configures the address used for the listener to listen on all IP
  // addresses and the given UDP port.
  //
  QUIC_ADDR Address = {0};
  QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
  QuicAddrSetPort(&Address, UdpPort);

  //
  // Load the server configuration based on the command line.
  //
  if (!ServerLoadConfiguration(argc, argv)) {
    return;
  }

  //
  // Create/allocate a new listener object.
  //
  if (QUIC_FAILED(Status = MsQuic->ListenerOpen(
                      Registration, ServerListenerCallback, NULL, &Listener))) {
    printf("ListenerOpen failed, 0x%x!\n", Status);
    shutdown();
  }

  //
  // Starts listening for incoming connections.
  //
  if (QUIC_FAILED(Status =
                      MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
    printf("ListenerStart failed, 0x%x!\n", Status);
    shutdown();
  }

  //
  // Continue listening for connections until the Enter key is pressed.
  //
  printf("Press Enter to exit.\n\n");
  (void)getchar();

  shutdown();
}

//
// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ClientStreamCallback(_In_ HQUIC Stream, _In_opt_ void* Context,
                         _Inout_ QUIC_STREAM_EVENT* Event) {
  UNREFERENCED_PARAMETER(Context);
  switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      free(Event->SEND_COMPLETE.ClientContext);
      printf("[strm][%p] Data sent\n", Stream);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      //
      // Data was received from the peer on the stream.
      //
      printf("[strm][%p] Data received\n", Stream);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      //
      // The peer gracefully shut down its send direction of the stream.
      //
      printf("[strm][%p] Peer aborted\n", Stream);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      //
      // The peer aborted its send direction of the stream.
      //
      printf("[strm][%p] Peer shut down\n", Stream);
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      //
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      //
      printf("[strm][%p] All done\n", Stream);
      if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
        MsQuic->StreamClose(Stream);
      }
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
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
        //
        // This will block until all outstanding child objects have been
        // closed.
        //
        MsQuic->RegistrationClose(Registration);
      }
      MsQuicClose(MsQuic);
    }
  };

  //
  // Open a handle to the library and get the API function table.
  //
  if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
    printf("MsQuicOpen2 failed, 0x%x!\n", Status);
    shutdown();
    return (int)Status;
  }

  //
  // Create a registration for the app's connections.
  //
  if (QUIC_FAILED(Status =
                      MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
    printf("RegistrationOpen failed, 0x%x!\n", Status);
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
