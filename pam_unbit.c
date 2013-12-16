#include <unistd.h>
#include <syslog.h>
#include <pam_modules.h>
#include <pam_modutil.h>
#include <pwd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define UNUSED __attribute__ ((unused))

#define UNBIT_MIN_UID 30000
#define UNBIT_EMPEROR_HOME_NS "/containers/"
#define UNBIT_EMPEROR_MAX_NS 64

int *emperor_ns_attach_fds(int fd) {

        ssize_t len;

        struct cmsghdr *cmsg;
        int *ret;
        int i;

        void *msg_control = malloc(CMSG_SPACE(sizeof(int) * UNBIT_EMPEROR_MAX_NS));
        memset(msg_control, 0, CMSG_SPACE(sizeof(int) * UNBIT_EMPEROR_MAX_NS));

        struct iovec iov;
	// uwsgi-setns + sizeof(int)
        iov.iov_base = malloc(11 + sizeof(int));
        iov.iov_len = 11 + sizeof(int);

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));

        msg.msg_name = NULL;
        msg.msg_namelen = 0;

        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        msg.msg_control = msg_control;
        msg.msg_controllen = CMSG_SPACE(sizeof(int) * UNBIT_EMPEROR_MAX_NS);

        msg.msg_flags = 0;

        len = recvmsg(fd, &msg, 0);
	free(iov.iov_base);
        if (len <= 0) {
		free(msg_control);
                return NULL;
        }

        cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg) {
		free(msg_control);
                return NULL;
	}

        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		free(msg_control);
                return NULL;
        }

        if ((size_t) (cmsg->cmsg_len - ((char *) CMSG_DATA(cmsg) - (char *) cmsg)) > (size_t) (sizeof(int) * (UNBIT_EMPEROR_MAX_NS + 1))) {
		free(msg_control);
                return NULL;
        }

        ret = malloc(sizeof(int) * (UNBIT_EMPEROR_MAX_NS + 1));
        for (i = 0; i < UNBIT_EMPEROR_MAX_NS + 1; i++) {
                ret[i] = -1;
        }
        memcpy(ret, CMSG_DATA(cmsg), cmsg->cmsg_len - ((char *) CMSG_DATA(cmsg) - (char *) cmsg));
        free(msg_control);

        return ret;
}


PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, int flags UNUSED, int argc, const char **argv) {
	char filename[102];
	char *account;

	int ret = pam_get_item(pamh, PAM_USER, (void *) &account);
        if (account == NULL || ret != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_CRIT, "[unbit] no account name");
                return PAM_SESSION_ERR;
        }

	struct passwd *pwd = pam_modutil_getpwnam(pamh, account);
        if (!pwd) {
                pam_syslog(pamh, LOG_CRIT, "[unbit] no uid");
                return PAM_SESSION_ERR;
        }

	if (pwd->pw_uid < UNBIT_MIN_UID) {
                return PAM_SUCCESS;
        }

	/*
		steps:
			- connect to /run/unbit/<uid>/ns.socket
			- receive fds
			- call setns for each one
			- on error deny access
	*/

	ret = snprintf(filename, 102, UNBIT_EMPEROR_HOME_NS "%s/run/ns.socket", account);
	if (ret <= 0 || ret > 102) {
		return PAM_PERM_DENIED;
	}

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(struct sockaddr_un));
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, filename, strlen(filename));

	int fd = socket(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (fd < 0) {
		pam_syslog(pamh, LOG_CRIT, "[unbit] socket() failed for %s: %s\n", account, strerror(errno));
		return PAM_PERM_DENIED;
	}

	struct pollfd upoll;
	upoll.fd = fd;
	upoll.events = POLLOUT;

	if (connect(fd, (struct sockaddr *)&sun, sizeof(struct sockaddr_un))) {
		pam_syslog(pamh, LOG_CRIT, "[unbit] connect() failed for %s: %s\n", account, strerror(errno));
		close(fd);
                return PAM_PERM_DENIED;
	}

	// max 3 seconds
	ret = poll(&upoll, 1, 3000);
	if (ret <= 0) {
		pam_syslog(pamh, LOG_CRIT, "[unbit] poll() failed for %s: %s\n", account, strerror(errno));
		close(fd);
                return PAM_PERM_DENIED;
	}

	int soopt = 0;
	socklen_t solen = sizeof(int);

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *) (&soopt), &solen) < 0) {
		pam_syslog(pamh, LOG_CRIT, "[unbit] getsockopt() failed for %s: %s\n", account, strerror(errno));
                close(fd);
                return PAM_PERM_DENIED;
	}

	if (soopt) {
		pam_syslog(pamh, LOG_CRIT, "[unbit] connect() failed for %s: %s\n", account, strerror(errno));
                close(fd);
                return PAM_PERM_DENIED;
	}

	upoll.events = POLLIN;

	ret = poll(&upoll, 1, 3000);
        if (ret <= 0) {
                pam_syslog(pamh, LOG_CRIT, "[unbit] poll() failed for %s: %s\n", account, strerror(errno));
                close(fd);
                return PAM_PERM_DENIED;
        }

	int *fds = emperor_ns_attach_fds(fd);
	close(fd);
	if (!fds) {
                pam_syslog(pamh, LOG_CRIT, "[unbit] emperor_ns_attach_fds() failed for %s: %s\n", account, strerror(errno));
                return PAM_PERM_DENIED;
	}

	int i;
	int applied = 0;
	for(i=0;i<UNBIT_EMPEROR_MAX_NS;i++) {
		if (fds[i] == -1) {
			break;
		}
		applied++;
		if (setns(fds[i], 0) < 0) {
			free(fds);
			pam_syslog(pamh, LOG_CRIT, "[unbit] setns() failed for %s: %s\n", account, strerror(errno));
                	return PAM_PERM_DENIED;
		}
	}

	free(fds);
	if (!applied) return PAM_PERM_DENIED;
        return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh UNUSED, int flags UNUSED, int argc UNUSED, const char **argv UNUSED) {
	return PAM_SUCCESS;
}
