#ifndef PHP_LIBVIRT_H
#define PHP_LIBVIRT_H 1

#ifdef ZTS
#include "TSRM.h"
#endif

#include <libvirt/libvirt.h>

ZEND_BEGIN_MODULE_GLOBALS(libvirt)
	char *last_error;
ZEND_END_MODULE_GLOBALS(libvirt)

#ifdef ZTS
#define LIBVIRT_G(v) TSRMG(libvirt_globals_id, zend_libvirt_globals *, v)
#else
#define LIBVIRT_G(v) (libvirt_globals.v)
#endif

#define PHP_LIBVIRT_WORLD_VERSION "0.3"
#define PHP_LIBVIRT_WORLD_EXTNAME "libvirt"


typedef struct _php_libvirt_connection {
    virConnectPtr conn;
} php_libvirt_connection;

typedef struct _php_libvirt_domain {
    virDomainPtr domain;
} php_libvirt_domain;


typedef struct _php_libvirt_cred_value {
	int count;
	int	type;
	char *result;
	unsigned int	resultlen;
} php_libvirt_cred_value;


#define PHP_LIBVIRT_CONNECTION_RES_NAME "Libvrit connection"
#define PHP_LIBVIRT_DOMAIN_RES_NAME "Libvrit domain"

PHP_MINIT_FUNCTION(libvirt);
PHP_MSHUTDOWN_FUNCTION(libvirt);
PHP_RINIT_FUNCTION(libvirt);
PHP_RSHUTDOWN_FUNCTION(libvirt);
PHP_MINFO_FUNCTION(libvirt);

PHP_FUNCTION(libvirt_get_last_error);
PHP_FUNCTION(libvirt_connect);
PHP_FUNCTION(libvirt_get_hostname);
PHP_FUNCTION(libvirt_node_get_info);
PHP_FUNCTION(libvirt_get_active_domain_count);
PHP_FUNCTION(libvirt_get_inactive_domain_count);
PHP_FUNCTION(libvirt_get_domain_count);
PHP_FUNCTION(libvirt_domain_lookup_by_name);
PHP_FUNCTION(libvirt_domain_get_xml_desc);
PHP_FUNCTION(libvirt_domain_get_info);
PHP_FUNCTION(libvirt_list_domains);
PHP_FUNCTION(libvirt_domain_get_uuid);
PHP_FUNCTION(libvirt_domain_get_uuid_string);
PHP_FUNCTION(libvirt_domain_get_name);
PHP_FUNCTION(libvirt_list_active_domains);
PHP_FUNCTION(libvirt_list_defined_domains);
PHP_FUNCTION(libvirt_domain_get_id);
PHP_FUNCTION(libvirt_domain_lookup_by_id);
PHP_FUNCTION(libvirt_domain_lookup_by_uuid);
PHP_FUNCTION(libvirt_domain_lookup_by_uuid_string);
PHP_FUNCTION(libvirt_domain_destroy);
PHP_FUNCTION(libvirt_domain_create);
PHP_FUNCTION(libvirt_domain_resume);
PHP_FUNCTION(libvirt_domain_shutdown);
PHP_FUNCTION(libvirt_domain_suspend);
PHP_FUNCTION(libvirt_domain_undefine);
PHP_FUNCTION(libvirt_domain_reboot);
PHP_FUNCTION(libvirt_domain_define_xml);
PHP_FUNCTION(libvirt_domain_create_xml);
PHP_FUNCTION(libvirt_domain_memory_peek);
#if LIBVIR_VERSION_NUMBER>=7005
PHP_FUNCTION(libvirt_domain_memory_stats);
#endif
PHP_FUNCTION(libvirt_domain_block_stats);
PHP_FUNCTION(libvirt_domain_interface_stats);
PHP_FUNCTION(libvirt_version);

 

extern zend_module_entry libvirt_module_entry;
#define phpext_libvirt_ptr &libvirt_module_entry

#endif
