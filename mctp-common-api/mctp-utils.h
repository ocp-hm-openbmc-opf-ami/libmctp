#ifndef __MCTP_UTILS_H__
#define __MCTP_UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <syslog.h>

/* MCTP packet definitions */
struct mctp_hdr_ext_ {
	uint16_t remote_id;
	uint8_t src;
	uint8_t flags_seq_tag;
} __attribute__((packed));

extern uint8_t g_verbose_level;

#define PCIE_GET_REMOTE_ID(x)	   (be16toh(x->remote_id))
#define PCIE_SET_REMOTE_ID(x, val) (x->remote_id |= (htobe16(val)))

static inline void mctp_sys_prlog(int level, const char *fmt, ...)
{
	va_list ap;

	(void)level;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
}

void mctp_sys_prlog(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

enum { MCTP_SYS_LOG_NONE = 0, MCTP_SYS_LOG_VERBOSE, MCTP_SYS_LOG_DEBUG };

#ifndef pr_fmt
#define pr_fmt(x) x
#endif

/* these should match the syslog-standard LOG_* definitions, for
 * easier use with syslog */
#define MCTP_SYS_LOG_ERR	 3
#define MCTP_SYS_LOG_WARNING 4
#define MCTP_SYS_LOG_NOTICE	 5
#define MCTP_SYS_LOG_INFO	 6
#define MCTP_SYS_LOG_DEBUG	 7

#define MCTP_SYS_ERR(fmt, ...)                                                \
	mctp_sys_prlog(MCTP_SYS_LOG_ERR, pr_fmt(fmt), ##__VA_ARGS__)

#define MCTP_SYS_WARN(fmt, ...)                                               \
	mctp_sys_prlog(MCTP_SYS_LOG_WARNING, pr_fmt(fmt), ##__VA_ARGS__)

#define MCTP_SYS_INFO(fmt, ...)                                               \
	mctp_sys_prlog(MCTP_SYS_LOG_INFO, pr_fmt(fmt), ##__VA_ARGS__)

#define MCTP_SYS_DEBUG(f_, ...)                                               \
	do {                                                                   \
		if (g_verbose_level >= MCTP_SYS_LOG_VERBOSE) {                \
			mctp_sys_prlog(MCTP_SYS_LOG_INFO, f_, ##__VA_ARGS__);     \
		}                                                              \
	} while (0)

#define MCTP_SYS_TRACE(f_, ...)                                               \
	do {                                                                   \
		if (g_verbose_level == MCTP_SYS_LOG_VERBOSE) {                \
			mctp_sys_prlog(MCTP_SYS_LOG_INFO, f_, ##__VA_ARGS__);     \
		}                                                              \
	} while (0)


int64_t mctp_millis();

#ifdef __cplusplus
}
#endif
#endif
