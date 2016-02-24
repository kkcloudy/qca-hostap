#ifndef __HAN_IOCTL_H
#define __HAN_IOCTL_H

enum han_ioctl_priv {
	HAN_IOCTL_PRIV_BANDSTEERING = 0,
};

struct han_ioctl_priv_args {
	enum han_ioctl_priv type;
	union {
		struct {
#define HAN_IOCTL_BANDSTEERING_ENABLE 0
#define HAN_IOCTL_BANDSTEERING_RSS_THRESHOLD 1
#define HAN_IOCTL_BANDSTEERING_ACCESS_LOAD 2
#define HAN_IOCTL_BANDSTEERING_DENY_COUNT 3
#define HAN_IOCTL_BANDSTEERING_DEBUG 4
#define HAN_IOCTL_BANDSTEERING_STATISTICS 5
#define OP_SET 	0x01
#define OP_GET	0x02

			unsigned int subtype;
			unsigned int op;
			int value;
			struct  {
				//non 5G capable
				u_int32_t	non_5g_capable;
				//5G capable
				u_int32_t	persist_to_2g;
				u_int32_t	excessive_load_5g_capable_to_5g;
				u_int32_t	excessive_load_5g_capable_to_2g;
				u_int32_t	steer_to_5g;
				u_int32_t	weak_2g_signal;
				//totally
				u_int32_t	total_2g;
				u_int32_t	total_5g;
			} bs_stat;
			
		} bandsteering;

		/*New cmd struct*/
	} u;
};


#endif
