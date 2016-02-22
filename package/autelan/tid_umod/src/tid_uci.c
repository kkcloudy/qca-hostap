#include <stdio.h>
#include <string.h>

#include "tid_debug.h"
#include "uci.h"

unsigned char tid_debug_level = 2;
struct uci_context *tid_ctx;
static struct uci_package *tid_package_open(char *name)
{
    struct uci_package *package = NULL;
    int err = 0;
    
    err = uci_load(tid_ctx, name, &package);
    if (err) {
        tid_debug_error("[tid]: open uci package(%s) failed\r\n", name);
    } else {
        tid_debug_trace("[tid]: open uci package(%s)\r\n", name);
    }

    return package;
}

static void tid_package_close(struct uci_package *p)
{
    if (tid_ctx && p) {
        uci_unload(tid_ctx, p);
        tid_debug_trace("[tid]: close uci package(%p)\r\n", p);
    }
}

static void tid_load_section(struct uci_section *s)
{
	struct uci_element *e = NULL;
    struct uci_option *o = NULL;    
	uci_foreach_element(&s->options, e) {
        o = uci_to_option(e);
        if (!strncmp(e->name, "debug_level", strlen(e->name)))
        {
            if (!strncmp(o->v.string, "error", strlen(o->v.string)))
            {
                tid_debug_level = 1;
            }
            if (!strncmp(o->v.string, "trace", strlen(o->v.string)))
            {
                tid_debug_level = 3;
            }
            else
            {
                tid_debug_level = 2;
            }
        }
    }
    
    return;
}

static int tid_load_packet(struct uci_package *pstmonitor)
{
  	struct uci_element *e = NULL;
    struct uci_section *s = NULL;

	uci_foreach_element(&pstmonitor->sections, e) {
		s = uci_to_section(e);
        tid_load_section(s);
	}
    
    return 0;
}

static int tid_uci_init(void)
{
    tid_ctx = uci_alloc_context();
    if (NULL == tid_ctx) {
        tid_debug_error("[tid]: open uci context failed");

        return -1;
    } else {
        tid_debug_trace("[tid]: open uci context");
    }

    return 0;
}

static void tid_uci_fini(void)
{
    if (tid_ctx) {
        uci_free_context(tid_ctx);

        tid_debug_trace("[tid]: close uci context");
    }

    return;
}

int tid_uci_load(void)
{
    struct uci_package *monitor = NULL;
    int err = 0;
    
    err = tid_uci_init();
    if (err < 0)
    {
        return err;
    }
    
    monitor = tid_package_open("tid");
    if (NULL == monitor) {
        tid_uci_fini();
        return -1;
    }

    err = tid_load_packet(monitor);
    tid_package_close(monitor);
    tid_uci_fini();
    
    return err;
}