package main

const (
	TCP_ESTABLISHED uint8 = iota + 1
	TCP_SYN_SENT uint8 = iota + 1
	TCP_SYN_RECV uint8 = iota + 1
	TCP_FIN_WAIT1 uint8 = iota + 1
	TCP_FIN_WAIT2 uint8 = iota + 1
	TCP_TIME_WAIT uint8 = iota + 1
	TCP_CLOSE uint8 = iota + 1
	TCP_CLOSE_WAIT uint8 = iota + 1
	TCP_LAST_ACK uint8 = iota + 1
	TCP_LISTEN uint8 = iota + 1
	TCP_CLOSING uint8 = iota + 1
)

func tcpStateString(state uint8) string {
	switch state {
	case TCP_ESTABLISHED:
		return "ESTABLISHED"
	case TCP_SYN_SENT:
		return "SYN_SENT"
	case TCP_SYN_RECV:
		return "SYN_RECV"
	case TCP_FIN_WAIT1:
		return "FIN_WAIT1"
	case TCP_FIN_WAIT2:
		return "FIN_WAIT2"
	case TCP_TIME_WAIT:
		return "TIME_WAIT"
	case TCP_CLOSE:
		return "CLOSED"
	case TCP_CLOSE_WAIT:
		return "CLOSE_WAIT"
	case TCP_LAST_ACK:
		return "LAST_ACK"
	case TCP_CLOSING:
		return "CLOSING"
	default:
		return ""
	}
}
