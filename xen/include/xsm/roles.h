/*
 *  This file contains the XSM roles.
 *
 *  This work is based on the original XSM dummy policy.
 *
 *  Author:  Daniel P. Smith, <dpsmith@apertussolutions.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#ifndef __XSM_ROLES_H__
#define __XSM_ROLES_H__

#include <xen/sched.h>

#define CLASSIC_DOM0_PRIVS (XSM_PLAT_CTRL | XSM_DOM_BUILD | XSM_DOM_SUPER | \
		XSM_DEV_EMUL | XSM_HW_CTRL | XSM_HW_SUPER | XSM_XENSTORE)

#define CLASSIC_HWDOM_PRIVS (XSM_HW_CTRL | XSM_DEV_EMUL)

/* Any access for which XSM_DEV_EMUL is the restriction, XSM_DOM_SUPER is an override */
#define DEV_EMU_PRIVS (XSM_DOM_SUPER | XSM_DEV_EMUL)

/* Anytime there is an XSM_TARGET check, XSM_SELF also applies, and XSM_DOM_SUPER is an override */
#define TARGET_PRIVS (XSM_TARGET | XSM_SELF | XSM_DOM_SUPER)

/* Anytime there is an XSM_XENSTORE check, XSM_DOM_SUPER is an override */
#define XENSTORE_PRIVS (XSM_XENSTORE | XSM_DOM_SUPER)

typedef uint32_t xsm_role_t;

static always_inline int xsm_validate_role(
    xsm_role_t allowed, struct domain *src, struct domain *target)
{
    if ( allowed & XSM_NONE )
        return 0;

    if ( (allowed & XSM_SELF) && ((!target) || (src == target)) )
        return 0;

    if ( (allowed & XSM_TARGET) && ((target) && (src->target == target)) )
        return 0;

    /* XSM_DEV_EMUL is the only domain role with a condition, i.e. the
     * role only applies to a domain's target.
     */
    if ( (allowed & XSM_DEV_EMUL) && (src->xsm_roles & XSM_DEV_EMUL)
        && (target) && (src->target == target) )
        return 0;

    /* Mask out SELF, TARGET, and DEV_EMUL as they have been handled */
    allowed &= !(XSM_SELF & XSM_TARGET & XSM_DEV_EMUL);

    /* Checks if the domain has one of the remaining roles set on it:
     *      XSM_PLAT_CTRL
     *      XSM_DOM_BUILD
     *      XSM_DOM_SUPER
     *      XSM_HW_CTRL
     *      XSM_HW_SUPER
     *      XSM_XENSTORE
     */
    if (src->xsm_roles & allowed)
        return 0;

    return -EPERM;
}

#endif __XSM_ROLES_H__
