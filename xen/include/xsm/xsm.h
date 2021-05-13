/*
 *  This file contains the XSM hook definitions for Xen.
 *
 *  This work is based on the LSM implementation in Linux 2.6.13.4.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  Contributors: Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#ifndef __XSM_H__
#define __XSM_H__

#include <xen/sched.h>
#include <xsm/roles.h>
#include <xen/multiboot.h>

#include <public/version.h>
#include <public/hvm/params.h>

typedef void xsm_op_t;
DEFINE_XEN_GUEST_HANDLE(xsm_op_t);

/* policy magic number (defined by XSM_MAGIC) */
typedef u32 xsm_magic_t;

#ifdef CONFIG_XSM_FLASK
#define XSM_MAGIC 0xf97cff8c
#else
#define XSM_MAGIC 0x0
#endif

struct xsm_operations {
    void (*security_domaininfo) (struct domain *d,
                                        struct xen_domctl_getdomaininfo *info);
    int (*domain_create) (struct domain *d, u32 ssidref);
    int (*getdomaininfo) (struct domain *d);
    int (*domctl_scheduler_op) (struct domain *d, int op);
    int (*sysctl_scheduler_op) (int op);
    int (*set_target) (struct domain *d, struct domain *e);
    int (*domctl) (struct domain *d, int cmd);
    int (*sysctl) (int cmd);
    int (*readconsole) (uint32_t clear);

    int (*evtchn_unbound) (struct domain *d, struct evtchn *chn, domid_t id2);
    int (*evtchn_interdomain) (struct domain *d1, struct evtchn *chn1,
                                        struct domain *d2, struct evtchn *chn2);
    void (*evtchn_close_post) (struct evtchn *chn);
    int (*evtchn_send) (struct domain *d, struct evtchn *chn);
    int (*evtchn_status) (struct domain *d, struct evtchn *chn);
    int (*evtchn_reset) (struct domain *d1, struct domain *d2);

    int (*grant_mapref) (struct domain *d1, struct domain *d2, uint32_t flags);
    int (*grant_unmapref) (struct domain *d1, struct domain *d2);
    int (*grant_setup) (struct domain *d1, struct domain *d2);
    int (*grant_transfer) (struct domain *d1, struct domain *d2);
    int (*grant_copy) (struct domain *d1, struct domain *d2);
    int (*grant_query_size) (struct domain *d1, struct domain *d2);

    int (*alloc_security_domain) (struct domain *d);
    void (*free_security_domain) (struct domain *d);
    int (*alloc_security_evtchns) (struct evtchn chn[], unsigned int nr);
    void (*free_security_evtchns) (struct evtchn chn[], unsigned int nr);
    char *(*show_security_evtchn) (struct domain *d, const struct evtchn *chn);
    int (*init_hardware_domain) (struct domain *d);

    int (*get_pod_target) (struct domain *d);
    int (*set_pod_target) (struct domain *d);
    int (*memory_exchange) (struct domain *d);
    int (*memory_adjust_reservation) (struct domain *d1, struct domain *d2);
    int (*memory_stat_reservation) (struct domain *d1, struct domain *d2);
    int (*memory_pin_page) (struct domain *d1, struct domain *d2, struct page_info *page);
    int (*add_to_physmap) (struct domain *d1, struct domain *d2);
    int (*remove_from_physmap) (struct domain *d1, struct domain *d2);
    int (*map_gmfn_foreign) (struct domain *d, struct domain *t);
    int (*claim_pages) (struct domain *d);

    int (*console_io) (struct domain *d, int cmd);

    int (*profile) (struct domain *d, int op);

    int (*kexec) (void);
    int (*schedop_shutdown) (struct domain *d1, struct domain *d2);

    char *(*show_irq_sid) (int irq);
    int (*map_domain_pirq) (struct domain *d);
    int (*map_domain_irq) (struct domain *d, int irq, const void *data);
    int (*unmap_domain_pirq) (struct domain *d);
    int (*unmap_domain_irq) (struct domain *d, int irq, const void *data);
    int (*bind_pt_irq) (struct domain *d, struct xen_domctl_bind_pt_irq *bind);
    int (*unbind_pt_irq) (struct domain *d, struct xen_domctl_bind_pt_irq *bind);
    int (*irq_permission) (struct domain *d, int pirq, uint8_t allow);
    int (*iomem_permission) (struct domain *d, uint64_t s, uint64_t e, uint8_t allow);
    int (*iomem_mapping) (struct domain *d, uint64_t s, uint64_t e, uint8_t allow);
    int (*pci_config_permission) (struct domain *d, uint32_t machine_bdf, uint16_t start, uint16_t end, uint8_t access);

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_PCI)
    int (*get_device_group) (uint32_t machine_bdf);
    int (*assign_device) (struct domain *d, uint32_t machine_bdf);
    int (*deassign_device) (struct domain *d, uint32_t machine_bdf);
#endif

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_DEVICE_TREE)
    int (*assign_dtdevice) (struct domain *d, const char *dtpath);
    int (*deassign_dtdevice) (struct domain *d, const char *dtpath);
#endif

    int (*resource_plug_core) (void);
    int (*resource_unplug_core) (void);
    int (*resource_plug_pci) (uint32_t machine_bdf);
    int (*resource_unplug_pci) (uint32_t machine_bdf);
    int (*resource_setup_pci) (uint32_t machine_bdf);
    int (*resource_setup_gsi) (int gsi);
    int (*resource_setup_misc) (void);

    int (*page_offline)(uint32_t cmd);
    int (*hypfs_op)(void);

    long (*do_xsm_op) (XEN_GUEST_HANDLE_PARAM(xsm_op_t) op);
#ifdef CONFIG_COMPAT
    int (*do_compat_op) (XEN_GUEST_HANDLE_PARAM(xsm_op_t) op);
#endif

    int (*hvm_param) (struct domain *d, unsigned long op);
    int (*hvm_control) (struct domain *d, unsigned long op);
    int (*hvm_param_altp2mhvm) (struct domain *d);
    int (*hvm_altp2mhvm_op) (struct domain *d, uint64_t mode, uint32_t op);
    int (*get_vnumainfo) (struct domain *d);

    int (*vm_event_control) (struct domain *d, int mode, int op);

#ifdef CONFIG_MEM_ACCESS
    int (*mem_access) (struct domain *d);
#endif

#ifdef CONFIG_HAS_MEM_PAGING
    int (*mem_paging) (struct domain *d);
#endif

#ifdef CONFIG_MEM_SHARING
    int (*mem_sharing) (struct domain *d);
#endif

    int (*platform_op) (uint32_t cmd);

#ifdef CONFIG_X86
    int (*do_mca) (void);
    int (*shadow_control) (struct domain *d, uint32_t op);
    int (*mem_sharing_op) (struct domain *d, struct domain *cd, int op);
    int (*apic) (struct domain *d, int cmd);
    int (*memtype) (uint32_t access);
    int (*machine_memory_map) (void);
    int (*domain_memory_map) (struct domain *d);
#define XSM_MMU_UPDATE_READ      1
#define XSM_MMU_UPDATE_WRITE     2
#define XSM_MMU_NORMAL_UPDATE    4
#define XSM_MMU_MACHPHYS_UPDATE  8
    int (*mmu_update) (struct domain *d, struct domain *t,
                       struct domain *f, uint32_t flags);
    int (*mmuext_op) (struct domain *d, struct domain *f);
    int (*update_va_mapping) (struct domain *d, struct domain *f, l1_pgentry_t pte);
    int (*priv_mapping) (struct domain *d, struct domain *t);
    int (*ioport_permission) (struct domain *d, uint32_t s, uint32_t e, uint8_t allow);
    int (*ioport_mapping) (struct domain *d, uint32_t s, uint32_t e, uint8_t allow);
    int (*pmu_op) (struct domain *d, unsigned int op);
#endif
    int (*dm_op) (struct domain *d);
    int (*xen_version) (uint32_t cmd);
    int (*domain_resource_map) (struct domain *d);
#ifdef CONFIG_ARGO
    int (*argo_enable) (const struct domain *d);
    int (*argo_register_single_source) (const struct domain *d,
                                        const struct domain *t);
    int (*argo_register_any_source) (const struct domain *d);
    int (*argo_send) (const struct domain *d, const struct domain *t);
#endif
};

extern struct xsm_operations *xsm_ops;

#define CALL_XSM_OP(op, ...)                            \
    do {                                                \
        if ( xsm_ops && xsm_ops->op )                   \
            return xsm_ops->op(__VA_ARGS__);            \
    } while ( 0 )

#define CALL_XSM_OP_NORET(op, ...)                      \
    do {                                                \
        if ( xsm_ops && xsm_ops->op ) {                 \
            xsm_ops->op(__VA_ARGS__);                   \
            return;                                     \
        }                                               \
    } while ( 0 )

#define XSM_ALLOWED_ROLES(def)                          \
    do {                                                \
        BUG_ON( !((def) & role) );                      \
    } while ( 0 )

static inline void xsm_security_domaininfo (struct domain *d,
                                        struct xen_domctl_getdomaininfo *info)
{
    CALL_XSM_OP_NORET(security_domaininfo,d, info);

    return;
}

static inline int xsm_domain_create (xsm_role_t role, struct domain *d, u32 ssidref)
{
    CALL_XSM_OP(domain_create, d, ssidref);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_getdomaininfo (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(getdomaininfo, d);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_domctl_scheduler_op (xsm_role_t role, struct domain *d, int cmd)
{
    CALL_XSM_OP(domctl_scheduler_op, d, cmd);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_sysctl_scheduler_op (xsm_role_t role, int cmd)
{
    CALL_XSM_OP(sysctl_scheduler_op, cmd);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_set_target (xsm_role_t role, struct domain *d, struct domain *e)
{
    CALL_XSM_OP(set_target, d, e);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_domctl (xsm_role_t role, struct domain *d, int cmd)
{
    CALL_XSM_OP(domctl, d, cmd);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS | XENSTORE_PRIVS | XSM_DOM_SUPER);
    switch ( cmd )
    {
    case XEN_DOMCTL_ioport_mapping:
    case XEN_DOMCTL_memory_mapping:
    case XEN_DOMCTL_bind_pt_irq:
    case XEN_DOMCTL_unbind_pt_irq:
        return xsm_validate_role(DEV_EMU_PRIVS, current->domain, d);
    case XEN_DOMCTL_getdomaininfo:
        return xsm_validate_role(XENSTORE_PRIVS, current->domain, d);
    default:
        return xsm_validate_role(XSM_DOM_SUPER, current->domain, d);
    }
}

static inline int xsm_sysctl (xsm_role_t role, int cmd)
{
    CALL_XSM_OP(sysctl, cmd);
    XSM_ALLOWED_ROLES(XSM_PLAT_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_readconsole (xsm_role_t role, uint32_t clear)
{
    CALL_XSM_OP(readconsole, clear);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_evtchn_unbound (xsm_role_t role, struct domain *d1, struct evtchn *chn,
                                                                    domid_t id2)
{
    CALL_XSM_OP(evtchn_unbound, d1, chn, id2);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, current->domain, d1);
}

static inline int xsm_evtchn_interdomain (xsm_role_t role, struct domain *d1,
                struct evtchn *chan1, struct domain *d2, struct evtchn *chan2)
{
    CALL_XSM_OP(evtchn_interdomain, d1, chan1, d2, chan2);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, d1, d2);
}

static inline void xsm_evtchn_close_post (struct evtchn *chn)
{
    CALL_XSM_OP_NORET(evtchn_close_post, chn);
    return;
}

static inline int xsm_evtchn_send (xsm_role_t role, struct domain *d, struct evtchn *chn)
{
    CALL_XSM_OP(evtchn_send, d, chn);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, d, NULL);
}

static inline int xsm_evtchn_status (xsm_role_t role, struct domain *d, struct evtchn *chn)
{
    CALL_XSM_OP(evtchn_status, d, chn);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_evtchn_reset (xsm_role_t role, struct domain *d1, struct domain *d2)
{
    CALL_XSM_OP(evtchn_reset, d1, d2);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_grant_mapref (xsm_role_t role, struct domain *d1, struct domain *d2,
                                                                uint32_t flags)
{
    CALL_XSM_OP(grant_mapref, d1, d2, flags);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_grant_unmapref (xsm_role_t role, struct domain *d1, struct domain *d2)
{
    CALL_XSM_OP(grant_unmapref, d1, d2);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_grant_setup (xsm_role_t role, struct domain *d1, struct domain *d2)
{
    CALL_XSM_OP(grant_setup, d1, d2);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_grant_transfer (xsm_role_t role, struct domain *d1, struct domain *d2)
{
    CALL_XSM_OP(grant_transfer, d1, d2);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_grant_copy (xsm_role_t role, struct domain *d1, struct domain *d2)
{
    CALL_XSM_OP(grant_copy, d1, d2);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_grant_query_size (xsm_role_t role, struct domain *d1, struct domain *d2)
{
    CALL_XSM_OP(grant_query_size, d1, d2);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_alloc_security_domain (struct domain *d)
{
    CALL_XSM_OP(alloc_security_domain, d);
    return 0;
}

static inline void xsm_free_security_domain (struct domain *d)
{
    CALL_XSM_OP_NORET(free_security_domain, d);
    return;
}

static inline int xsm_alloc_security_evtchns(
    struct evtchn chn[], unsigned int nr)
{
    CALL_XSM_OP(alloc_security_evtchns, chn, nr);
    return 0;
}

static inline void xsm_free_security_evtchns(
    struct evtchn chn[], unsigned int nr)
{
    CALL_XSM_OP_NORET(free_security_evtchns, chn, nr);
    return;
}

static inline char *xsm_show_security_evtchn (struct domain *d, const struct evtchn *chn)
{
    CALL_XSM_OP(show_security_evtchn, d, chn);
    return NULL;
}

static inline int xsm_init_hardware_domain (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(init_hardware_domain, d);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_get_pod_target (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(get_pod_target, d);
    XSM_ALLOWED_ROLES(XSM_DOM_SUPER);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_set_pod_target (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(set_pod_target, d);
    XSM_ALLOWED_ROLES(XSM_DOM_SUPER);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_memory_exchange (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(memory_exchange, d);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_memory_adjust_reservation (xsm_role_t role, struct domain *d1, struct
                                                                    domain *d2)
{
    CALL_XSM_OP(memory_adjust_reservation, d1, d2);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_memory_stat_reservation (xsm_role_t role, struct domain *d1,
                                                            struct domain *d2)
{
    CALL_XSM_OP(memory_stat_reservation, d1, d2);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_memory_pin_page(xsm_role_t role, struct domain *d1, struct domain *d2,
                                      struct page_info *page)
{
    CALL_XSM_OP(memory_pin_page, d1, d2, page);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_add_to_physmap(xsm_role_t role, struct domain *d1, struct domain *d2)
{
    CALL_XSM_OP(add_to_physmap, d1, d2);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_remove_from_physmap(xsm_role_t role, struct domain *d1, struct domain *d2)
{
    CALL_XSM_OP(remove_from_physmap, d1, d2);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d1, d2);
}

static inline int xsm_map_gmfn_foreign (xsm_role_t role, struct domain *d, struct domain *t)
{
    CALL_XSM_OP(map_gmfn_foreign, d, t);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d, t);
}

static inline int xsm_claim_pages(xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(claim_pages, d);
    XSM_ALLOWED_ROLES(XSM_DOM_SUPER);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_console_io (xsm_role_t role, struct domain *d, int cmd)
{
    CALL_XSM_OP(console_io, d, cmd);
    XSM_ALLOWED_ROLES(XSM_NONE|XSM_DOM_SUPER);
    if ( d->is_console )
        return xsm_validate_role(XSM_NONE, d, NULL);
#ifdef CONFIG_VERBOSE_DEBUG
    if ( cmd == CONSOLEIO_write )
        return xsm_validate_role(XSM_NONE, d, NULL);
#endif
    return xsm_validate_role(XSM_DOM_SUPER, d, NULL);
}

static inline int xsm_profile (xsm_role_t role, struct domain *d, int op)
{
    CALL_XSM_OP(profile, d, op);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, d, NULL);
}

static inline int xsm_kexec (xsm_role_t role)
{
    CALL_XSM_OP(kexec);
    XSM_ALLOWED_ROLES(XSM_PLAT_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_schedop_shutdown (xsm_role_t role, struct domain *d1, struct domain *d2)
{
    CALL_XSM_OP(schedop_shutdown, d1, d2);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, d1, d2);
}

static inline char *xsm_show_irq_sid (int irq)
{
    CALL_XSM_OP(show_irq_sid, irq);
    return NULL;
}

static inline int xsm_map_domain_pirq (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(map_domain_pirq, d);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_map_domain_irq (xsm_role_t role, struct domain *d, int irq, void *data)
{
    CALL_XSM_OP(map_domain_irq, d, irq, data);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_unmap_domain_pirq (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(unmap_domain_pirq, d);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_unmap_domain_irq (xsm_role_t role, struct domain *d, int irq, void *data)
{
    CALL_XSM_OP(unmap_domain_irq, d, irq, data);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_bind_pt_irq(xsm_role_t role, struct domain *d,
                                  struct xen_domctl_bind_pt_irq *bind)
{
    CALL_XSM_OP(bind_pt_irq, d, bind);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_unbind_pt_irq(xsm_role_t role, struct domain *d,
                                    struct xen_domctl_bind_pt_irq *bind)
{
    CALL_XSM_OP(unbind_pt_irq, d, bind);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_irq_permission (xsm_role_t role, struct domain *d, int pirq, uint8_t allow)
{
    CALL_XSM_OP(irq_permission, d, pirq, allow);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_iomem_permission (xsm_role_t role, struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    CALL_XSM_OP(iomem_permission, d, s, e, allow);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_iomem_mapping (xsm_role_t role, struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    CALL_XSM_OP(iomem_mapping, d, s, e, allow);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_pci_config_permission (xsm_role_t role, struct domain *d, uint32_t machine_bdf, uint16_t start, uint16_t end, uint8_t access)
{
    CALL_XSM_OP(pci_config_permission, d, machine_bdf, start, end, access);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_PCI)
static inline int xsm_get_device_group(xsm_role_t role, uint32_t machine_bdf)
{
    CALL_XSM_OP(get_device_group, machine_bdf);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_assign_device(xsm_role_t role, struct domain *d, uint32_t machine_bdf)
{
    CALL_XSM_OP(assign_device, d, machine_bdf);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_deassign_device(xsm_role_t role, struct domain *d, uint32_t machine_bdf)
{
    CALL_XSM_OP(deassign_device, d, machine_bdf);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}
#endif /* HAS_PASSTHROUGH && HAS_PCI) */

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_DEVICE_TREE)
static inline int xsm_assign_dtdevice(xsm_role_t role, struct domain *d,
                                      const char *dtpath)
{
    CALL_XSM_OP(assign_dtdevice, d, dtpath);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_deassign_dtdevice(xsm_role_t role, struct domain *d,
                                        const char *dtpath)
{
    CALL_XSM_OP(deassign_dtdevice, d, dtpath);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

#endif /* HAS_PASSTHROUGH && HAS_DEVICE_TREE */

static inline int xsm_resource_plug_pci (xsm_role_t role, uint32_t machine_bdf)
{
    CALL_XSM_OP(resource_plug_pci, machine_bdf);
    XSM_ALLOWED_ROLES(XSM_HW_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_resource_unplug_pci (xsm_role_t role, uint32_t machine_bdf)
{
    CALL_XSM_OP(resource_unplug_pci, machine_bdf);
    XSM_ALLOWED_ROLES(XSM_HW_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_resource_plug_core (xsm_role_t role)
{
    CALL_XSM_OP(resource_plug_core);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_resource_unplug_core (xsm_role_t role)
{
    CALL_XSM_OP(resource_unplug_core);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_resource_setup_pci (xsm_role_t role, uint32_t machine_bdf)
{
    CALL_XSM_OP(resource_setup_pci, machine_bdf);
    XSM_ALLOWED_ROLES(XSM_HW_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_resource_setup_gsi (xsm_role_t role, int gsi)
{
    CALL_XSM_OP(resource_setup_gsi, gsi);
    XSM_ALLOWED_ROLES(XSM_HW_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_resource_setup_misc (xsm_role_t role)
{
    CALL_XSM_OP(resource_setup_misc);
    XSM_ALLOWED_ROLES(XSM_HW_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_page_offline(xsm_role_t role, uint32_t cmd)
{
    CALL_XSM_OP(page_offline, cmd);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_hypfs_op(xsm_role_t role)
{
    CALL_XSM_OP(hypfs_op);
    XSM_ALLOWED_ROLES(XSM_PLAT_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline long xsm_do_xsm_op (XEN_GUEST_HANDLE_PARAM(xsm_op_t) op)
{
    CALL_XSM_OP(do_xsm_op, op);
    return -ENOSYS;
}

#ifdef CONFIG_COMPAT
static inline int xsm_do_compat_op (XEN_GUEST_HANDLE_PARAM(xsm_op_t) op)
{
    CALL_XSM_OP(do_compat_op, op);
    return -ENOSYS;
}
#endif

static inline int xsm_hvm_param (xsm_role_t role, struct domain *d, unsigned long op)
{
    CALL_XSM_OP(hvm_param, d, op);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_hvm_control(xsm_role_t role, struct domain *d, unsigned long op)
{
    CALL_XSM_OP(hvm_control, d, op);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_hvm_param_altp2mhvm (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(hvm_param_altp2mhvm, d);
    XSM_ALLOWED_ROLES(XSM_DOM_SUPER);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_hvm_altp2mhvm_op (xsm_role_t role, struct domain *d, uint64_t mode, uint32_t op)
{
    CALL_XSM_OP(hvm_altp2mhvm_op, d, mode, op);
    XSM_ALLOWED_ROLES(TARGET_PRIVS | DEV_EMU_PRIVS);

    switch ( mode )
    {
    case XEN_ALTP2M_mixed:
        return xsm_validate_role(TARGET_PRIVS, current->domain, d);
    case XEN_ALTP2M_external:
        return xsm_validate_role(DEV_EMU_PRIVS, current->domain, d);
    case XEN_ALTP2M_limited:
        if ( HVMOP_altp2m_vcpu_enable_notify == op )
            return xsm_validate_role(TARGET_PRIVS, current->domain, d);
        return xsm_validate_role(DEV_EMU_PRIVS, current->domain, d);
    default:
        return -EPERM;
    }
}

static inline int xsm_get_vnumainfo (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(get_vnumainfo, d);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_vm_event_control (xsm_role_t role, struct domain *d, int mode, int op)
{
    CALL_XSM_OP(vm_event_control, d, mode, op);
    XSM_ALLOWED_ROLES(XSM_DOM_SUPER);
    return xsm_validate_role(role, current->domain, d);
}

#ifdef CONFIG_MEM_ACCESS
static inline int xsm_mem_access (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(mem_access, d);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}
#endif

#ifdef CONFIG_HAS_MEM_PAGING
static inline int xsm_mem_paging (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(mem_paging, d);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}
#endif

#ifdef CONFIG_MEM_SHARING
static inline int xsm_mem_sharing (xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(mem_sharing, d);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}
#endif

static inline int xsm_platform_op (xsm_role_t role, uint32_t op)
{
    CALL_XSM_OP(platform_op, op);
    XSM_ALLOWED_ROLES(XSM_PLAT_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

#ifdef CONFIG_X86
static inline int xsm_do_mca(xsm_role_t role)
{
    CALL_XSM_OP(do_mca);
    XSM_ALLOWED_ROLES(XSM_PLAT_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_shadow_control (xsm_role_t role, struct domain *d, uint32_t op)
{
    CALL_XSM_OP(shadow_control, d, op);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_mem_sharing_op (xsm_role_t role, struct domain *d, struct domain *cd, int op)
{
    CALL_XSM_OP(mem_sharing_op, d, cd, op);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, current->domain, cd);
}

static inline int xsm_apic (xsm_role_t role, struct domain *d, int cmd)
{
    CALL_XSM_OP(apic, d, cmd);
    XSM_ALLOWED_ROLES(XSM_HW_CTRL);
    return xsm_validate_role(role, d, NULL);
}

static inline int xsm_machine_memory_map(xsm_role_t role)
{
    CALL_XSM_OP(machine_memory_map);
    XSM_ALLOWED_ROLES(XSM_PLAT_CTRL);
    return xsm_validate_role(role, current->domain, NULL);
}

static inline int xsm_domain_memory_map(xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(domain_memory_map, d);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_mmu_update (xsm_role_t role, struct domain *d, struct domain *t,
                                  struct domain *f, uint32_t flags)
{
    int rc = 0;
    CALL_XSM_OP(mmu_update, d, t, f, flags);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    if ( f != dom_io )
        rc = xsm_validate_role(role, d, f);
    if ( evaluate_nospec(t) && !rc )
        rc = xsm_validate_role(role, d, t);
    return rc;
}

static inline int xsm_mmuext_op (xsm_role_t role, struct domain *d, struct domain *f)
{
    CALL_XSM_OP(mmuext_op, d, f);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d, f);
}

static inline int xsm_update_va_mapping(xsm_role_t role, struct domain *d, struct domain *f,
                                                            l1_pgentry_t pte)
{
    CALL_XSM_OP(update_va_mapping, d, f, pte);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d, f);
}

static inline int xsm_priv_mapping(xsm_role_t role, struct domain *d, struct domain *t)
{
    CALL_XSM_OP(priv_mapping, d, t);
    XSM_ALLOWED_ROLES(TARGET_PRIVS);
    return xsm_validate_role(role, d, t);
}

static inline int xsm_ioport_permission (xsm_role_t role, struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    CALL_XSM_OP(ioport_permission, d, s, e, allow);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_ioport_mapping (xsm_role_t role, struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    CALL_XSM_OP(ioport_mapping, d, s, e, allow);
    XSM_ALLOWED_ROLES(XSM_NONE);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_pmu_op (xsm_role_t role, struct domain *d, unsigned int op)
{
    CALL_XSM_OP(pmu_op, d, op);
    XSM_ALLOWED_ROLES(XSM_NONE | XSM_DOM_SUPER);
    switch ( op )
    {
    case XENPMU_init:
    case XENPMU_finish:
    case XENPMU_lvtpc_set:
    case XENPMU_flush:
        return xsm_validate_role(XSM_NONE, d, current->domain);
    default:
        return xsm_validate_role(XSM_DOM_SUPER, d, current->domain);
    }
}

#endif /* CONFIG_X86 */

static inline int xsm_dm_op(xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(dm_op, d);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

static inline int xsm_xen_version (xsm_role_t role, uint32_t op)
{
    CALL_XSM_OP(xen_version, op);
    XSM_ALLOWED_ROLES(XSM_NONE | XSM_PLAT_CTRL);
    switch ( op )
    {
    case XENVER_version:
    case XENVER_platform_parameters:
    case XENVER_get_features:
        /* These sub-ops ignore the permission checks and return data. */
        block_speculation();
        return 0;
    case XENVER_extraversion:
    case XENVER_compile_info:
    case XENVER_capabilities:
    case XENVER_changeset:
    case XENVER_pagesize:
    case XENVER_guest_handle:
        /* These MUST always be accessible to any guest by default. */
        return xsm_validate_role(XSM_NONE, current->domain, NULL);
    default:
        return xsm_validate_role(XSM_PLAT_CTRL, current->domain, NULL);
    }
}

static inline int xsm_domain_resource_map(xsm_role_t role, struct domain *d)
{
    CALL_XSM_OP(domain_resource_map, d);
    XSM_ALLOWED_ROLES(DEV_EMU_PRIVS);
    return xsm_validate_role(role, current->domain, d);
}

#ifdef CONFIG_ARGO
static inline int xsm_argo_enable(const struct domain *d)
{
    CALL_XSM_OP(argo_enable, d);
    return 0;
}

static inline int xsm_argo_register_single_source(const struct domain *d,
                                                  const struct domain *t)
{
    CALL_XSM_OP(argo_register_single_source, d, t);
    return 0;
}

static inline int xsm_argo_register_any_source(const struct domain *d)
{
    CALL_XSM_OP(argo_register_any_source, d);
    return 0;
}

static inline int xsm_argo_send(const struct domain *d, const struct domain *t)
{
    CALL_XSM_OP(argo_send, d, t);
    return 0;
}

#endif /* CONFIG_ARGO */

extern int register_xsm(struct xsm_operations *ops);

extern struct xsm_operations dummy_xsm_ops;
extern void xsm_fixup_ops(struct xsm_operations *ops);

#ifdef CONFIG_XSM_FLASK
extern void flask_init(const void *policy_buffer, size_t policy_size);
#else
static inline void flask_init(const void *policy_buffer, size_t policy_size)
{
}
#endif

#ifdef CONFIG_XSM_FLASK_POLICY
extern const unsigned char xsm_flask_init_policy[];
extern const unsigned int xsm_flask_init_policy_size;
#endif

#ifdef CONFIG_XSM_SILO
extern void silo_init(void);
#else
static inline void silo_init(void) {}
#endif

#ifdef CONFIG_MULTIBOOT
extern int xsm_multiboot_init(unsigned long *module_map,
                              const multiboot_info_t *mbi);
extern int xsm_multiboot_policy_init(unsigned long *module_map,
                                     const multiboot_info_t *mbi,
                                     void **policy_buffer,
                                     size_t *policy_size);
#endif

#ifdef CONFIG_HAS_DEVICE_TREE
/*
 * Initialize XSM
 *
 * On success, return 1 if using SILO mode else 0.
 */
extern int xsm_dt_init(void);
extern int xsm_dt_policy_init(void **policy_buffer, size_t *policy_size);
extern bool has_xsm_magic(paddr_t);
#endif

#endif /* __XSM_H */
