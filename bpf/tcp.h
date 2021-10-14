#include "netinet/tcp.h"

// only handle client tcp state.
static inline __u8 tcp_state_update(__u8 current_state, __u8 flag, int snd) {
	__u8 state = current_state;
	if (flag & TH_RST) {
		return TCP_CLOSE;
	}
	switch (current_state) {
		case TCP_ESTABLISHED:
			if ((flag & TH_FIN) && snd == 1) {
				state = TCP_FIN_WAIT1;
			} else if ((flag & TH_FIN) && snd == 0) {
				state = TCP_CLOSE_WAIT;
			}
			break;
		case TCP_SYN_SENT:
			if (((flag & TH_SYN) && (flag & TH_ACK)) && snd == 0) {
				state = TCP_ESTABLISHED;
			} else if ((flag & TH_SYN) && snd == 0) {
				state = TCP_SYN_RECV;
			}
			break;
		case TCP_SYN_RECV:
			break;
		case TCP_FIN_WAIT1:
			if (((flag & TH_FIN) && (flag & TH_ACK)) && snd == 0) {
				// state = TCP_TIME_WAIT;
				state = TCP_CLOSE;
			} else if ((flag & TH_ACK) && snd == 0) {
				state = TCP_FIN_WAIT2;
			}
			break;
		case TCP_FIN_WAIT2:
			if ((flag & TH_FIN) && snd == 0) {
				// state = TCP_TIME_WAIT;
				state = TCP_CLOSE;
			}
			break;
		case TCP_TIME_WAIT:
			break;
		case TCP_CLOSE:
			if ((flag & TH_SYN) && snd == 1) {
				state = TCP_SYN_SENT;
			}
			break;
		case TCP_CLOSE_WAIT:
			if ((flag & TH_FIN) && snd == 1) {
				state = TCP_LAST_ACK;
			}
			break;
		case TCP_LAST_ACK:
			if ((flag & TH_ACK) && snd == 0) {
				state = TCP_CLOSE;
			}
			break;
		case TCP_LISTEN:
			break;
		case TCP_CLOSING:
			break;
	}
	return state;
}
