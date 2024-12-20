/*
 * Copyright (c) 2012 Robert Nagy <robert@openbsd.org>
 * All rights reserved.
 *
 */

#include <sys/param.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <login_cap.h>
#include <bsd_auth.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	struct passwd *pwd;
	const char *user;
	char *crypt_password, *password, *style = NULL;
	char *class = NULL;
	int pam_err, retry;
	auth_session_t *as;
	login_cap_t *lc;

	(void)argc;
	(void)argv;

	if ((as = auth_open()) == NULL)
		return (PAM_AUTH_ERR);

	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	if ((pwd = getpwnam(user)) == NULL)
		return (PAM_USER_UNKNOWN);

	/* If the user specified a login class, use it */
	if (!class && pwd && pwd->pw_class && pwd->pw_class[0] != '\0')
		class = strdup(pwd->pw_class);

	/* Get login class; if invalid style treat like unknown user. */
	lc = login_getclass(class);
	if (lc && (style = login_getstyle(lc, style, "auth-pam")) == NULL) {
		login_close(lc);
		return (PAM_USER_UNKNOWN);
	}
	login_close(lc);

	/* get password */
	for (retry = 0; retry < 3; ++retry) {
		pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
		    (const char **)&password, NULL);
		if (pam_err == PAM_SUCCESS)
			break;
	}
	if (pam_err == PAM_CONV_ERR)
		return (pam_err);
	if (pam_err != PAM_SUCCESS)
		return (PAM_AUTH_ERR);

	if (auth_userokay((char *)user, NULL, NULL, (char *)password))
		pam_err = PAM_SUCCESS;
	else
		pam_err = PAM_AUTH_ERR;

	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_bsdauth");
#endif
