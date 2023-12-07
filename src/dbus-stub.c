#include "ell/dbus.h"
#include "ell/ell.h"
#include <stdbool.h>
#include <stddef.h>

#define INTERFACES_LEN 256

struct interface {
  char *interface;
  struct {
    char *object;
    void *user_data;
  } objects[256];
  size_t objects_len;
  l_dbus_interface_setup_func_t setup_func;
  l_dbus_destroy_func_t destroy;
};

static struct interface *get_interfaces(size_t **modify_len) {
  static size_t len = 0;
  static struct interface interfaces[INTERFACES_LEN] = {0};

  *modify_len = &len;
  return interfaces;
}

bool fake_dbus_register_interface(const char *interface,
                                  l_dbus_interface_setup_func_t setup_func,
                                  l_dbus_destroy_func_t destroy) {
  size_t *len;
  struct interface *interfaces = get_interfaces(&len);

  l_info("Registering interface '%s'", interface);

  if (*len < INTERFACES_LEN) {
    interfaces[(*len)++] = (struct interface){.interface = l_strdup(interface),
                                              .setup_func = setup_func,
                                              .destroy = destroy};

    return true;
  }

  L_WARN_ON(true);
  return false;
}

bool fake_dbus_unregister_interface(const char *interface) { return true; }

bool fake_dbus_object_add_interface(const char *object, const char *interface,
                                    void *user_data) {
  size_t *len;
  struct interface *interfaces = get_interfaces(&len);

  l_info("Adding object '%s' for interface '%s'", object, interface);

  for (size_t i = 0; i < *len; i++) {
    struct interface *iface = &interfaces[i];

    if (!strcmp(interface, iface->interface)) {
      iface->objects[iface->objects_len].object = l_strdup(object);
      iface->objects[iface->objects_len].user_data = user_data;

      iface->objects_len++;

      iface->setup_func(NULL);

      return true;
    }
  }

  L_WARN_ON(true);
  return false;
}

bool fake_dbus_object_remove_interface(const char *object,
                                       const char *interface) {
  size_t *len;
  struct interface *interfaces = get_interfaces(&len);

  l_info("Removing object '%s' for interface '%s'", object, interface);

  for (size_t i = 0; i < *len; i++) {
    struct interface *iface = &interfaces[i];

    if (!strcmp(interface, iface->interface)) {
      l_info("Found interface '%s', removing object '%s'", interface, object);

      for (size_t j = 0; j < iface->objects_len; j++) {
        if (!strcmp(object, iface->objects[j].object)) {
          iface->destroy(iface->objects[j].user_data);
          iface->objects[j].object[0] = '\0';

          return true;
        }
      }

      L_WARN_ON(true);
      return false;
    }
  }

  L_WARN_ON(true);
  return false;
}
