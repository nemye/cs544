#include <string>

// With a proper JSON parsing setup, we would parse the messages into these PDUs
struct SPOQ_HEADER {
  std::string version = {};
  std::string status = {};
  size_t sensor_id = {};
};

struct SPOQ_PDU {
  SPOQ_HEADER header = {};
  std::string data = {};
};

enum class SPOQ_STATE {
  UNKNOWN,
  INIT,         // Initial state before anything is sent/received
  NEGOTIATE,    // Handshake in progress (e.g., client sends version negotiation
                // and waits for server reply)
  ESTABLISHED,  // Handshake succeeded, ready to send/receive sensor data
  WAITING,    // Idle but expecting input (e.g., waiting for data or keep-alive)
  SENDING,    // Actively sending data
  RECEIVING,  // Actively receiving data
  ERROR,      // Protocol or auth failure, bad state, etc.
  CLOSED      // Connection intentionally closed (normal or error exit)
};

inline std::string ToString(SPOQ_STATE state) {
    switch (state) {
        case SPOQ_STATE::INIT:        return "[SPOQ] STATE INIT";
        case SPOQ_STATE::NEGOTIATE:   return "[SPOQ] STATE NEGOTIATE";
        case SPOQ_STATE::ESTABLISHED: return "[SPOQ] STATE ESTABLISHED";
        case SPOQ_STATE::WAITING:     return "[SPOQ] STATE WAITING";
        case SPOQ_STATE::SENDING:     return "[SPOQ] STATE SENDING";
        case SPOQ_STATE::RECEIVING:   return "[SPOQ] STATE RECEIVING";
        case SPOQ_STATE::ERROR:       return "[SPOQ] STATE ERROR";
        case SPOQ_STATE::CLOSED:      return "[SPOQ] STATE CLOSED";
        default:                      return "[SPOQ] STATE UNKNOWN";
    }
}

void setSpoqState(SPOQ_STATE& state, const SPOQ_STATE next){
  state = next;
  std::cout << ToString(next) << "\n";
}