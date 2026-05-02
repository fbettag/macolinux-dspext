#include <Network/Network.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <xpc/xpc.h>

typedef void *nw_endpoint_private_t;

typedef nw_endpoint_private_t (*nw_endpoint_create_application_service_fn)(const char *, const uuid_t);
typedef nw_endpoint_private_t (*nw_endpoint_create_application_service_with_alias_fn)(const char *,
                                                                                      const char *);
typedef nw_endpoint_private_t (*nw_endpoint_create_bonjour_service_fn)(const char *, const char *, const char *);
typedef xpc_object_t (*nw_endpoint_copy_dictionary_fn)(nw_endpoint_private_t);
typedef nw_endpoint_private_t (*nw_endpoint_create_from_dictionary_fn)(xpc_object_t);
typedef void (*nw_endpoint_set_uuid_fn)(nw_endpoint_private_t, const uuid_t);
typedef void (*nw_endpoint_set_string_fn)(nw_endpoint_private_t, const char *);
typedef const char *(*nw_endpoint_get_string_fn)(nw_endpoint_private_t);
typedef xpc_object_t (*nw_parameters_copy_xpc_fn)(nw_parameters_t);
typedef bool (*nw_parameters_get_bool_fn)(nw_parameters_t);
typedef void (*nw_parameters_set_bool_fn)(nw_parameters_t, bool);
typedef const char *(*nw_parameters_get_string_fn)(nw_parameters_t);
typedef void (*nw_parameters_set_string_fn)(nw_parameters_t, const char *);
typedef void (*nw_parameters_require_netagent_uuid_fn)(nw_parameters_t, const uuid_t);
typedef void (*nw_parameters_set_netagent_classes_fn)(nw_parameters_t, xpc_object_t, xpc_object_t);
typedef xpc_object_t (*nw_network_agent_copy_dictionary_for_uuid_fn)(const uuid_t);
typedef xpc_object_t (*nw_path_copy_xpc_fn)(nw_path_t);
typedef char *(*nw_path_copy_description_fn)(nw_path_t);
typedef nw_parameters_t (*nw_parameters_create_application_service_quic_fn)(void);
typedef nw_browse_descriptor_t (*nw_browse_descriptor_create_application_service_with_bundle_id_fn)(
    const char *, const char *);
typedef void (*nw_browse_descriptor_set_bool_fn)(nw_browse_descriptor_t, bool);
typedef void (*nw_browse_descriptor_set_u32_fn)(nw_browse_descriptor_t, uint32_t);
typedef nw_group_descriptor_t (*nw_group_descriptor_create_application_service_fn)(nw_endpoint_t,
                                                                                   const uuid_t);
typedef nw_interface_t (*nw_interface_create_with_name_fn)(const char *);
typedef void (*nw_parameters_require_interface_fn)(nw_parameters_t, nw_interface_t);

struct connection_options {
    const char *required_interface_name;
    const char *required_netagent_uuid;
    const char *required_netagent_domain;
    const char *required_netagent_type;
};

enum browse_parameters_mode {
    browse_parameters_mode_application_service,
    browse_parameters_mode_application_service_quic,
};

struct bool_override {
    bool is_set;
    bool value;
};

struct browse_options {
    const char *required_interface_name;
    const char *required_netagent_uuid;
    const char *required_netagent_domain;
    const char *required_netagent_type;
    enum browse_parameters_mode parameters_mode;
    const char *source_application_bundle_id;
    const char *source_application_external_bundle_id;
    const char *effective_bundle_id;
    struct bool_override include_ble;
    struct bool_override include_screen_off_devices;
    struct bool_override use_awdl;
    struct bool_override use_p2p;
    struct bool_override stricter_path_scoping;
    struct bool_override include_txt_record;
    struct bool_override sign_results;
};

static void usage(const char *name) {
    fprintf(stderr,
            "usage:\n"
            "  %s appsvc SERVICE UUID [set-service-id UUID] [set-agent-id UUID] [set-preferred-agent-id UUID] [set-device-name NAME] [set-device-id ID]\n"
            "  %s appsvc-alias SERVICE ALIAS [set-service-id UUID] [set-agent-id UUID] [set-preferred-agent-id UUID] [set-device-name NAME] [set-device-id ID]\n"
            "  %s connect-appsvc-alias SERVICE ALIAS UUID SECONDS [require-interface NAME] [require-netagent UUID] [require-netagent-class DOMAIN TYPE] [set-agent-id UUID] [set-preferred-agent-id UUID] [set-device-name NAME] [set-device-id ID]\n"
            "  %s browse-appsvc-bundle SERVICE BUNDLE SECONDS [endpoints-only 0|1] [device-types MASK] [browse-scope SCOPE] [parameters-mode appsvc|appsvc-quic] [source-app-bundle-id BUNDLE] [external-source-app-bundle-id BUNDLE] [effective-bundle-id BUNDLE] [include-ble 0|1] [include-screen-off 0|1] [use-awdl 0|1] [use-p2p 0|1] [stricter-path-scoping 0|1] [include-txt-record 0|1] [sign-results 0|1] [require-interface NAME] [require-netagent UUID] [require-netagent-class DOMAIN TYPE]\n"
            "  %s group-appsvc SERVICE ALIAS UUID [set-agent-id UUID] [set-preferred-agent-id UUID] [set-device-name NAME] [set-device-id ID]\n"
            "  %s agent-dict UUID\n"
            "  %s bonjour NAME TYPE DOMAIN\n",
            name, name, name, name, name, name, name);
    exit(2);
}

static void *lookup(const char *symbol) {
    void *ptr = dlsym(RTLD_DEFAULT, symbol);
    if (!ptr) {
        fprintf(stderr, "%s unavailable\n", symbol);
        exit(1);
    }
    return ptr;
}

static void parse_uuid_or_die(const char *text, uuid_t out) {
    if (uuid_parse(text, out) != 0) {
        fprintf(stderr, "invalid UUID: %s\n", text);
        exit(2);
    }
}

static void dump_xpc_object(xpc_object_t object, const char *label) {
    if (!object) {
        printf("%s=nil\n", label);
        return;
    }
    char *description = xpc_copy_description(object);
    if (description) {
        printf("%s=%s\n", label, description);
        free(description);
    } else {
        printf("%s.description=nil\n", label);
    }
}

static void dump_endpoint_dictionary(nw_endpoint_private_t endpoint, const char *label) {
    nw_endpoint_copy_dictionary_fn copy_dictionary =
        (nw_endpoint_copy_dictionary_fn)lookup("nw_endpoint_copy_dictionary");
    xpc_object_t dictionary = copy_dictionary(endpoint);
    if (!dictionary) {
        printf("%s.dictionary=nil\n", label);
        return;
    }

    char dictionary_label[128];
    snprintf(dictionary_label, sizeof(dictionary_label), "%s.dictionary", label);
    dump_xpc_object(dictionary, dictionary_label);
    xpc_release(dictionary);
}

static void dump_parameters_netagents(nw_parameters_t parameters, const char *label) {
    const struct {
        const char *symbol;
        const char *suffix;
    } copies[] = {
        {"nw_parameters_copy_required_netagent_uuids", "required_netagent_uuids"},
        {"nw_parameters_copy_required_netagent_domains", "required_netagent_domains"},
        {"nw_parameters_copy_required_netagent_types", "required_netagent_types"},
        {"nw_parameters_copy_preferred_netagent_uuids", "preferred_netagent_uuids"},
        {"nw_parameters_copy_preferred_netagent_domains", "preferred_netagent_domains"},
        {"nw_parameters_copy_preferred_netagent_types", "preferred_netagent_types"},
        {"nw_parameters_copy_prohibited_netagent_uuids", "prohibited_netagent_uuids"},
        {"nw_parameters_copy_prohibited_netagent_domains", "prohibited_netagent_domains"},
        {"nw_parameters_copy_prohibited_netagent_types", "prohibited_netagent_types"},
        {"nw_parameters_copy_avoided_netagent_uuids", "avoided_netagent_uuids"},
        {"nw_parameters_copy_avoided_netagent_domains", "avoided_netagent_domains"},
        {"nw_parameters_copy_avoided_netagent_types", "avoided_netagent_types"},
    };

    for (size_t i = 0; i < sizeof(copies) / sizeof(copies[0]); i++) {
        nw_parameters_copy_xpc_fn copy = (nw_parameters_copy_xpc_fn)dlsym(RTLD_DEFAULT, copies[i].symbol);
        char value_label[160];
        snprintf(value_label, sizeof(value_label), "%s.%s", label, copies[i].suffix);
        if (!copy) {
            printf("%s=unavailable\n", value_label);
            continue;
        }
        xpc_object_t value = copy(parameters);
        dump_xpc_object(value, value_label);
        if (value) {
            xpc_release(value);
        }
    }
}

static void dump_parameters_bool(nw_parameters_t parameters, const char *symbol, const char *label) {
    nw_parameters_get_bool_fn getter = (nw_parameters_get_bool_fn)dlsym(RTLD_DEFAULT, symbol);
    if (!getter) {
        printf("%s=unavailable\n", label);
        return;
    }
    printf("%s=%s\n", label, getter(parameters) ? "true" : "false");
}

static void dump_parameters_flags(nw_parameters_t parameters, const char *label) {
    const struct {
        const char *symbol;
        const char *suffix;
    } flags[] = {
        {"nw_parameters_get_include_peer_to_peer", "include_peer_to_peer"},
        {"nw_parameters_get_include_ble", "include_ble"},
        {"nw_parameters_get_include_screen_off_devices", "include_screen_off_devices"},
        {"nw_parameters_get_use_awdl", "use_awdl"},
        {"nw_parameters_get_use_p2p", "use_p2p"},
        {"nw_parameters_get_stricter_path_scoping", "stricter_path_scoping"},
        {"nw_parameters_get_local_only", "local_only"},
    };

    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        char value_label[160];
        snprintf(value_label, sizeof(value_label), "%s.%s", label, flags[i].suffix);
        dump_parameters_bool(parameters, flags[i].symbol, value_label);
    }
}

static void dump_parameters_string(nw_parameters_t parameters, const char *symbol, const char *label) {
    nw_parameters_get_string_fn getter = (nw_parameters_get_string_fn)dlsym(RTLD_DEFAULT, symbol);
    if (!getter) {
        printf("%s=unavailable\n", label);
        return;
    }
    const char *value = getter(parameters);
    printf("%s=%s\n", label, value ? value : "nil");
}

static void dump_network_agent_dictionary(const char *uuid_text, const char *label) {
    uuid_t uuid;
    parse_uuid_or_die(uuid_text, uuid);
    nw_network_agent_copy_dictionary_for_uuid_fn copy_dictionary =
        (nw_network_agent_copy_dictionary_for_uuid_fn)lookup("nw_network_agent_copy_dictionary_for_uuid");
    xpc_object_t dictionary = copy_dictionary(uuid);
    dump_xpc_object(dictionary, label);
    if (dictionary) {
        size_t data_len = 0;
        const uint8_t *data = xpc_dictionary_get_data(dictionary, "data", &data_len);
        if (data) {
            printf("%s.data.len=%zu\n", label, data_len);
            printf("%s.data.ascii=", label);
            for (size_t i = 0; i < data_len; i++) {
                uint8_t value = data[i];
                putchar(value >= 0x20 && value <= 0x7e ? value : '.');
            }
            putchar('\n');
            printf("%s.data.hex=", label);
            for (size_t i = 0; i < data_len; i++) {
                printf("%02x", data[i]);
            }
            putchar('\n');
        } else {
            printf("%s.data=nil\n", label);
        }
    }
    if (dictionary) {
        xpc_release(dictionary);
    }
}

static void dump_path_xpc(nw_path_t path, const char *symbol, const char *label) {
    nw_path_copy_xpc_fn copy = (nw_path_copy_xpc_fn)dlsym(RTLD_DEFAULT, symbol);
    if (!copy) {
        printf("%s=unavailable\n", label);
        return;
    }
    xpc_object_t value = copy(path);
    dump_xpc_object(value, label);
    if (value) {
        xpc_release(value);
    }
}

static void dump_path_endpoint(nw_path_t path, const char *symbol, const char *label) {
    typedef nw_endpoint_t (*copy_endpoint_fn)(nw_path_t);
    copy_endpoint_fn copy = (copy_endpoint_fn)dlsym(RTLD_DEFAULT, symbol);
    if (!copy) {
        printf("%s=unavailable\n", label);
        return;
    }
    nw_endpoint_t endpoint = copy(path);
    if (!endpoint) {
        printf("%s=nil\n", label);
        return;
    }
    dump_endpoint_dictionary((nw_endpoint_private_t)endpoint, label);
    nw_release(endpoint);
}

static void dump_path_group(nw_path_t path, const char *label) {
    typedef nw_group_descriptor_t (*copy_group_fn)(nw_path_t);
    copy_group_fn copy = (copy_group_fn)dlsym(RTLD_DEFAULT, "nw_path_copy_group_descriptor");
    if (!copy) {
        printf("%s=unavailable\n", label);
        return;
    }
    nw_group_descriptor_t group = copy(path);
    if (!group) {
        printf("%s=nil\n", label);
        return;
    }
    __block int index = 0;
    nw_group_descriptor_enumerate_endpoints(group, ^bool(nw_endpoint_t member) {
        char member_label[128];
        snprintf(member_label, sizeof(member_label), "%s.member[%d]", label, index++);
        dump_endpoint_dictionary((nw_endpoint_private_t)member, member_label);
        return true;
    });
    printf("%s.members.count=%d\n", label, index);
    nw_release(group);
}

static void dump_connection_path(nw_connection_t connection, const char *label) {
    nw_path_t path = nw_connection_copy_current_path(connection);
    if (!path) {
        printf("%s.path=nil\n", label);
        return;
    }

    nw_path_copy_description_fn copy_description =
        (nw_path_copy_description_fn)dlsym(RTLD_DEFAULT, "nw_path_copy_description");
    if (copy_description) {
        char *description = copy_description(path);
        if (description) {
            printf("%s.path.description=%s\n", label, description);
            free(description);
        } else {
            printf("%s.path.description=nil\n", label);
        }
    }
    dump_path_xpc(path, "nw_path_copy_netagent_dictionary", "path.netagent_dictionary");
    dump_path_xpc(path, "nw_path_copy_inactive_agent_uuids", "path.inactive_agent_uuids");
    dump_path_endpoint(path, "nw_path_copy_endpoint", "path.endpoint");
    dump_path_endpoint(path, "nw_path_copy_effective_remote_endpoint", "path.effective_remote_endpoint");
    dump_path_endpoint(path, "nw_path_copy_effective_local_endpoint", "path.effective_local_endpoint");
    dump_path_group(path, "path.group");
    nw_release(path);
}

static void dump_string_getter(nw_endpoint_private_t endpoint, const char *symbol, const char *label) {
    nw_endpoint_get_string_fn getter = (nw_endpoint_get_string_fn)dlsym(RTLD_DEFAULT, symbol);
    if (!getter) {
        printf("%s=unavailable\n", label);
        return;
    }
    const char *value = getter(endpoint);
    printf("%s=%s\n", label, value ? value : "nil");
}

static const char *state_name(nw_connection_state_t state) {
    switch (state) {
    case nw_connection_state_invalid:
        return "invalid";
    case nw_connection_state_waiting:
        return "waiting";
    case nw_connection_state_preparing:
        return "preparing";
    case nw_connection_state_ready:
        return "ready";
    case nw_connection_state_failed:
        return "failed";
    case nw_connection_state_cancelled:
        return "cancelled";
    default:
        return "unknown";
    }
}

static const char *browser_state_name(nw_browser_state_t state) {
    switch (state) {
    case nw_browser_state_invalid:
        return "invalid";
    case nw_browser_state_ready:
        return "ready";
    case nw_browser_state_failed:
        return "failed";
    case nw_browser_state_cancelled:
        return "cancelled";
    case nw_browser_state_waiting:
        return "waiting";
    default:
        return "unknown";
    }
}

static nw_endpoint_private_t create_appsvc(const char *service, const char *uuid_text) {
    uuid_t service_id;
    parse_uuid_or_die(uuid_text, service_id);

    nw_endpoint_create_application_service_fn create =
        (nw_endpoint_create_application_service_fn)lookup("nw_endpoint_create_application_service");
    nw_endpoint_private_t endpoint = create(service, service_id);
    if (!endpoint) {
        fprintf(stderr, "nw_endpoint_create_application_service returned nil\n");
        exit(1);
    }
    return endpoint;
}

static nw_endpoint_private_t create_appsvc_alias(const char *service, const char *alias) {
    nw_endpoint_create_application_service_with_alias_fn create =
        (nw_endpoint_create_application_service_with_alias_fn)lookup(
            "nw_endpoint_create_application_service_with_alias");
    nw_endpoint_private_t endpoint = create(service, alias);
    if (!endpoint) {
        fprintf(stderr, "nw_endpoint_create_application_service_with_alias returned nil\n");
        exit(1);
    }
    return endpoint;
}

static nw_endpoint_private_t create_bonjour(const char *name, const char *type, const char *domain) {
    nw_endpoint_create_bonjour_service_fn create =
        (nw_endpoint_create_bonjour_service_fn)lookup("nw_endpoint_create_bonjour_service");
    nw_endpoint_private_t endpoint = create(name, type, domain);
    if (!endpoint) {
        fprintf(stderr, "nw_endpoint_create_bonjour_service returned nil\n");
        exit(1);
    }
    return endpoint;
}

static void apply_appsvc_option(nw_endpoint_private_t endpoint, int *index, int argc, char **argv) {
    const char *option = argv[*index];
    if (strcmp(option, "set-service-id") == 0) {
        if (*index + 1 >= argc) {
            usage(argv[0]);
        }
        uuid_t value;
        parse_uuid_or_die(argv[*index + 1], value);
        nw_endpoint_set_uuid_fn setter =
            (nw_endpoint_set_uuid_fn)lookup("nw_endpoint_set_service_identifier");
        setter(endpoint, value);
        *index += 2;
        return;
    }
    if (strcmp(option, "set-agent-id") == 0) {
        if (*index + 1 >= argc) {
            usage(argv[0]);
        }
        uuid_t value;
        parse_uuid_or_die(argv[*index + 1], value);
        nw_endpoint_set_uuid_fn setter =
            (nw_endpoint_set_uuid_fn)lookup("nw_endpoint_set_agent_identifier");
        setter(endpoint, value);
        *index += 2;
        return;
    }
    if (strcmp(option, "set-preferred-agent-id") == 0) {
        if (*index + 1 >= argc) {
            usage(argv[0]);
        }
        uuid_t value;
        parse_uuid_or_die(argv[*index + 1], value);
        nw_endpoint_set_uuid_fn setter =
            (nw_endpoint_set_uuid_fn)lookup("nw_endpoint_set_preferred_agent_identifier");
        setter(endpoint, value);
        *index += 2;
        return;
    }
    if (strcmp(option, "set-device-name") == 0) {
        if (*index + 1 >= argc) {
            usage(argv[0]);
        }
        nw_endpoint_set_string_fn setter =
            (nw_endpoint_set_string_fn)lookup("nw_endpoint_set_device_name");
        setter(endpoint, argv[*index + 1]);
        *index += 2;
        return;
    }
    if (strcmp(option, "set-device-id") == 0) {
        if (*index + 1 >= argc) {
            usage(argv[0]);
        }
        nw_endpoint_set_string_fn setter =
            (nw_endpoint_set_string_fn)lookup("nw_endpoint_set_device_id");
        setter(endpoint, argv[*index + 1]);
        *index += 2;
        return;
    }

    fprintf(stderr, "unknown appsvc option: %s\n", option);
    usage(argv[0]);
}

static void require_interface_on_parameters(nw_parameters_t parameters, const char *required_interface_name);

static bool parse_bool_text(const char *text) {
    if (strcmp(text, "1") == 0 || strcmp(text, "true") == 0 || strcmp(text, "yes") == 0) {
        return true;
    }
    if (strcmp(text, "0") == 0 || strcmp(text, "false") == 0 || strcmp(text, "no") == 0) {
        return false;
    }
    fprintf(stderr, "invalid boolean: %s\n", text);
    exit(2);
}

static void parse_bool_override(struct bool_override *target, const char *text) {
    target->is_set = true;
    target->value = parse_bool_text(text);
}

static void apply_parameters_bool_override(nw_parameters_t parameters,
                                           const char *symbol,
                                           const char *label,
                                           struct bool_override override) {
    if (!override.is_set) {
        return;
    }
    nw_parameters_set_bool_fn setter = (nw_parameters_set_bool_fn)lookup(symbol);
    setter(parameters, override.value);
    printf("%s=%s\n", label, override.value ? "true" : "false");
}

static void apply_parameters_string_override(nw_parameters_t parameters,
                                             const char *symbol,
                                             const char *label,
                                             const char *value) {
    if (!value) {
        return;
    }
    nw_parameters_set_string_fn setter = (nw_parameters_set_string_fn)lookup(symbol);
    setter(parameters, value);
    printf("%s=%s\n", label, value);
}

static void require_netagent_on_parameters(nw_parameters_t parameters, const char *uuid_text) {
    if (!uuid_text) {
        return;
    }
    uuid_t uuid;
    parse_uuid_or_die(uuid_text, uuid);
    nw_parameters_require_netagent_uuid_fn require_netagent =
        (nw_parameters_require_netagent_uuid_fn)lookup("nw_parameters_require_netagent_uuid");
    require_netagent(parameters, uuid);
    printf("parameters.required_netagent=%s\n", uuid_text);
    dump_network_agent_dictionary(uuid_text, "parameters.required_netagent.dictionary");
}

static void require_netagent_class_on_parameters(nw_parameters_t parameters,
                                                 const char *domain,
                                                 const char *type) {
    if (!domain && !type) {
        return;
    }
    if (!domain || !type) {
        fprintf(stderr, "require-netagent-class requires DOMAIN and TYPE\n");
        exit(2);
    }
    nw_parameters_set_netagent_classes_fn set_classes =
        (nw_parameters_set_netagent_classes_fn)lookup("nw_parameters_set_required_netagent_classes");
    xpc_object_t domains = xpc_array_create(NULL, 0);
    xpc_object_t types = xpc_array_create(NULL, 0);
    xpc_array_set_string(domains, XPC_ARRAY_APPEND, domain);
    xpc_array_set_string(types, XPC_ARRAY_APPEND, type);
    set_classes(parameters, domains, types);
    printf("parameters.required_netagent_class.domain=%s\n", domain);
    printf("parameters.required_netagent_class.type=%s\n", type);
    xpc_release(types);
    xpc_release(domains);
}

static void run_connection(nw_endpoint_private_t endpoint,
                           int seconds,
                           const struct connection_options *options) {
    nw_parameters_create_application_service_quic_fn create_parameters =
        (nw_parameters_create_application_service_quic_fn)lookup(
            "nw_parameters_create_application_service_quic");
    nw_parameters_t parameters = create_parameters();
    if (!parameters) {
        fprintf(stderr, "nw_parameters_create_application_service_quic returned nil\n");
        exit(1);
    }
    nw_parameters_set_include_peer_to_peer(parameters, true);
    require_interface_on_parameters(parameters, options ? options->required_interface_name : NULL);
    require_netagent_on_parameters(parameters, options ? options->required_netagent_uuid : NULL);
    require_netagent_class_on_parameters(parameters,
                                         options ? options->required_netagent_domain : NULL,
                                         options ? options->required_netagent_type : NULL);
    dump_parameters_netagents(parameters, "parameters");

    nw_connection_t connection = nw_connection_create((nw_endpoint_t)endpoint, parameters);
    if (!connection) {
        fprintf(stderr, "nw_connection_create returned nil\n");
        exit(1);
    }

    dispatch_queue_t queue = dispatch_queue_create("macolinux.network-endpoint-c-probe", NULL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    nw_connection_set_queue(connection, queue);
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
        printf("connection.state=%s", state_name(state));
        if (error) {
            printf(" error=%d", nw_error_get_error_code(error));
        }
        printf("\n");
        if (state == nw_connection_state_preparing || state == nw_connection_state_waiting ||
            state == nw_connection_state_ready || state == nw_connection_state_failed) {
            dump_connection_path(connection, "connection");
        }
        fflush(stdout);
        if (state == nw_connection_state_ready || state == nw_connection_state_failed ||
            state == nw_connection_state_cancelled) {
            dispatch_semaphore_signal(done);
        }
    });

    nw_connection_start(connection);
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)seconds * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(done, timeout) != 0) {
        printf("timeout.cancel\n");
        fflush(stdout);
        nw_connection_cancel(connection);
        dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
    }

    nw_release(connection);
    nw_release(parameters);
}

static void require_interface_on_parameters(nw_parameters_t parameters, const char *required_interface_name) {
    if (!required_interface_name) {
        return;
    }
    nw_interface_create_with_name_fn create_interface =
        (nw_interface_create_with_name_fn)lookup("nw_interface_create_with_name");
    nw_parameters_require_interface_fn require_interface =
        (nw_parameters_require_interface_fn)lookup("nw_parameters_require_interface");
    nw_interface_t required_interface = create_interface(required_interface_name);
    if (!required_interface) {
        fprintf(stderr, "nw_interface_create_with_name returned nil for %s\n",
                required_interface_name);
        exit(1);
    }
    require_interface(parameters, required_interface);
    nw_release(required_interface);
    printf("parameters.required_interface=%s\n", required_interface_name);
}

static void run_appsvc_browser(const char *service,
                               const char *bundle_id,
                               int seconds,
                               bool endpoints_only,
                               uint32_t device_types,
                               bool has_device_types,
                               uint32_t browse_scope,
                               bool has_browse_scope,
                               const struct browse_options *options) {
    nw_browse_descriptor_create_application_service_with_bundle_id_fn create_descriptor =
        (nw_browse_descriptor_create_application_service_with_bundle_id_fn)lookup(
            "nw_browse_descriptor_create_application_service_with_bundle_id");
    nw_browse_descriptor_t descriptor = create_descriptor(service, bundle_id);
    if (!descriptor) {
        fprintf(stderr, "nw_browse_descriptor_create_application_service_with_bundle_id returned nil\n");
        exit(1);
    }

    nw_browse_descriptor_set_bool_fn set_endpoints_only =
        (nw_browse_descriptor_set_bool_fn)dlsym(
            RTLD_DEFAULT, "nw_browse_descriptor_set_discover_application_service_endpoints_only");
    if (set_endpoints_only) {
        set_endpoints_only(descriptor, endpoints_only);
    } else {
        printf("descriptor.endpoints_only=unavailable\n");
    }
    printf("descriptor.service=%s bundle=%s endpoints_only=%s\n",
           service, bundle_id, endpoints_only ? "true" : "false");
    if (has_device_types) {
        nw_browse_descriptor_set_u32_fn set_device_types =
            (nw_browse_descriptor_set_u32_fn)lookup("nw_browse_descriptor_set_device_types");
        set_device_types(descriptor, device_types);
        printf("descriptor.device_types=0x%x\n", device_types);
    }
    if (has_browse_scope) {
        nw_browse_descriptor_set_u32_fn set_browse_scope =
            (nw_browse_descriptor_set_u32_fn)lookup("nw_browse_descriptor_set_browse_scope");
        set_browse_scope(descriptor, browse_scope);
        printf("descriptor.browse_scope=0x%x\n", browse_scope);
    }
    if (options && options->include_txt_record.is_set) {
        nw_browse_descriptor_set_bool_fn set_include_txt_record =
            (nw_browse_descriptor_set_bool_fn)lookup("nw_browse_descriptor_set_include_txt_record");
        set_include_txt_record(descriptor, options->include_txt_record.value);
        printf("descriptor.include_txt_record=%s\n",
               options->include_txt_record.value ? "true" : "false");
    }
    if (options && options->sign_results.is_set) {
        nw_browse_descriptor_set_bool_fn set_sign_results =
            (nw_browse_descriptor_set_bool_fn)lookup("nw_browse_descriptor_set_sign_results");
        set_sign_results(descriptor, options->sign_results.value);
        printf("descriptor.sign_results=%s\n", options->sign_results.value ? "true" : "false");
    }

    nw_parameters_t parameters = NULL;
    if (!options || options->parameters_mode == browse_parameters_mode_application_service) {
        parameters = nw_parameters_create_application_service();
    } else {
        nw_parameters_create_application_service_quic_fn create_quic =
            (nw_parameters_create_application_service_quic_fn)lookup(
                "nw_parameters_create_application_service_quic");
        parameters = create_quic();
    }
    if (!parameters) {
        fprintf(stderr, "failed to create browse parameters\n");
        exit(1);
    }
    nw_parameters_set_include_peer_to_peer(parameters, true);
    if (options) {
        apply_parameters_string_override(parameters,
                                         "nw_parameters_set_source_application_by_bundle_id",
                                         "parameters.source_application_bundle_id.override",
                                         options->source_application_bundle_id);
        apply_parameters_string_override(parameters,
                                         "nw_parameters_set_source_application_by_external_bundle_id",
                                         "parameters.source_application_external_bundle_id.override",
                                         options->source_application_external_bundle_id);
        apply_parameters_string_override(parameters,
                                         "nw_parameters_set_effective_bundle_id",
                                         "parameters.effective_bundle_id.override",
                                         options->effective_bundle_id);
        apply_parameters_bool_override(parameters,
                                       "nw_parameters_set_include_ble",
                                       "parameters.include_ble.override",
                                       options->include_ble);
        apply_parameters_bool_override(parameters,
                                       "nw_parameters_set_include_screen_off_devices",
                                       "parameters.include_screen_off_devices.override",
                                       options->include_screen_off_devices);
        apply_parameters_bool_override(parameters,
                                       "nw_parameters_set_use_awdl",
                                       "parameters.use_awdl.override",
                                       options->use_awdl);
        apply_parameters_bool_override(parameters,
                                       "nw_parameters_set_use_p2p",
                                       "parameters.use_p2p.override",
                                       options->use_p2p);
        apply_parameters_bool_override(parameters,
                                       "nw_parameters_set_stricter_path_scoping",
                                       "parameters.stricter_path_scoping.override",
                                       options->stricter_path_scoping);
        require_interface_on_parameters(parameters, options->required_interface_name);
        require_netagent_on_parameters(parameters, options->required_netagent_uuid);
        require_netagent_class_on_parameters(parameters,
                                             options->required_netagent_domain,
                                             options->required_netagent_type);
    }
    dump_parameters_string(parameters, "nw_parameters_get_effective_bundle_id", "parameters.effective_bundle_id");
    dump_parameters_flags(parameters, "parameters");
    dump_parameters_netagents(parameters, "parameters");

    nw_browser_t browser = nw_browser_create(descriptor, parameters);
    if (!browser) {
        fprintf(stderr, "nw_browser_create returned nil\n");
        exit(1);
    }
    dispatch_queue_t queue = dispatch_queue_create("macolinux.network-endpoint-c-probe.browser", NULL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    nw_browser_set_queue(browser, queue);
    nw_browser_set_state_changed_handler(browser, ^(nw_browser_state_t state, nw_error_t error) {
        printf("browser.state=%s", browser_state_name(state));
        if (error) {
            printf(" error=%d", nw_error_get_error_code(error));
        }
        printf("\n");
        fflush(stdout);
        if (state == nw_browser_state_failed || state == nw_browser_state_cancelled) {
            dispatch_semaphore_signal(done);
        }
    });
    nw_browser_set_browse_results_changed_handler(
        browser, ^(nw_browse_result_t old_result, nw_browse_result_t new_result, bool batch_complete) {
            (void)old_result;
            printf("browser.result batch_complete=%s\n", batch_complete ? "true" : "false");
            nw_endpoint_t result_endpoint = nw_browse_result_copy_endpoint(new_result);
            if (result_endpoint) {
                dump_endpoint_dictionary((nw_endpoint_private_t)result_endpoint, "result.endpoint");
                nw_release(result_endpoint);
            } else {
                printf("result.endpoint=nil\n");
            }
            size_t interface_count = nw_browse_result_get_interfaces_count(new_result);
            printf("result.interfaces.count=%zu\n", interface_count);
            nw_browse_result_enumerate_interfaces(new_result, ^bool(nw_interface_t interface) {
                const char *name = nw_interface_get_name(interface);
                printf("result.interface=%s\n", name ? name : "nil");
                return true;
            });
            fflush(stdout);
        });

    nw_browser_start(browser);
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)seconds * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(done, timeout) != 0) {
        printf("browser.timeout\n");
        fflush(stdout);
        nw_browser_cancel(browser);
        dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
    }

    nw_release(browser);
    nw_release(parameters);
    nw_release(descriptor);
}

static void run_appsvc_group(nw_endpoint_private_t endpoint, const char *uuid_text) {
    uuid_t group_id;
    parse_uuid_or_die(uuid_text, group_id);
    nw_group_descriptor_create_application_service_fn create_group =
        (nw_group_descriptor_create_application_service_fn)lookup(
            "nw_group_descriptor_create_application_service");
    nw_group_descriptor_t group = create_group((nw_endpoint_t)endpoint, group_id);
    if (!group) {
        fprintf(stderr, "nw_group_descriptor_create_application_service returned nil\n");
        exit(1);
    }
    printf("group.raw=%p\n", group);
    __block int index = 0;
    nw_group_descriptor_enumerate_endpoints(group, ^bool(nw_endpoint_t member) {
        char label[64];
        snprintf(label, sizeof(label), "group.member[%d]", index++);
        dump_endpoint_dictionary((nw_endpoint_private_t)member, label);
        return true;
    });
    printf("group.members.count=%d\n", index);
    nw_release(group);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
    }

    nw_endpoint_private_t endpoint = NULL;
    if (strcmp(argv[1], "agent-dict") == 0) {
        if (argc != 3) {
            usage(argv[0]);
        }
        dump_network_agent_dictionary(argv[2], "agent.dictionary");
        return 0;
    }
    if (strcmp(argv[1], "browse-appsvc-bundle") == 0) {
        if (argc < 5) {
            usage(argv[0]);
        }
        char *end = NULL;
        long seconds = strtol(argv[4], &end, 10);
        if (!end || *end != '\0' || seconds < 1 || seconds > 120) {
            fprintf(stderr, "invalid SECONDS: %s\n", argv[4]);
            exit(2);
        }
        bool endpoints_only = false;
        bool has_device_types = false;
        uint32_t device_types = 0;
        bool has_browse_scope = false;
        uint32_t browse_scope = 0;
        struct browse_options options = {
            .required_interface_name = NULL,
            .parameters_mode = browse_parameters_mode_application_service,
        };
        int index = 5;
        while (index < argc) {
            if (strcmp(argv[index], "endpoints-only") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                endpoints_only = atoi(argv[index + 1]) != 0;
                index += 2;
            } else if (strcmp(argv[index], "device-types") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                char *end_value = NULL;
                unsigned long value = strtoul(argv[index + 1], &end_value, 0);
                if (!end_value || *end_value != '\0' || value > UINT32_MAX) {
                    fprintf(stderr, "invalid device-types: %s\n", argv[index + 1]);
                    exit(2);
                }
                has_device_types = true;
                device_types = (uint32_t)value;
                index += 2;
            } else if (strcmp(argv[index], "browse-scope") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                char *end_value = NULL;
                unsigned long value = strtoul(argv[index + 1], &end_value, 0);
                if (!end_value || *end_value != '\0' || value > UINT32_MAX) {
                    fprintf(stderr, "invalid browse-scope: %s\n", argv[index + 1]);
                    exit(2);
                }
                has_browse_scope = true;
                browse_scope = (uint32_t)value;
                index += 2;
            } else if (strcmp(argv[index], "parameters-mode") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                if (strcmp(argv[index + 1], "appsvc") == 0) {
                    options.parameters_mode = browse_parameters_mode_application_service;
                } else if (strcmp(argv[index + 1], "appsvc-quic") == 0) {
                    options.parameters_mode = browse_parameters_mode_application_service_quic;
                } else {
                    fprintf(stderr, "invalid parameters-mode: %s\n", argv[index + 1]);
                    exit(2);
                }
                index += 2;
            } else if (strcmp(argv[index], "source-app-bundle-id") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                options.source_application_bundle_id = argv[index + 1];
                index += 2;
            } else if (strcmp(argv[index], "external-source-app-bundle-id") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                options.source_application_external_bundle_id = argv[index + 1];
                index += 2;
            } else if (strcmp(argv[index], "effective-bundle-id") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                options.effective_bundle_id = argv[index + 1];
                index += 2;
            } else if (strcmp(argv[index], "include-ble") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                parse_bool_override(&options.include_ble, argv[index + 1]);
                index += 2;
            } else if (strcmp(argv[index], "include-screen-off") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                parse_bool_override(&options.include_screen_off_devices, argv[index + 1]);
                index += 2;
            } else if (strcmp(argv[index], "use-awdl") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                parse_bool_override(&options.use_awdl, argv[index + 1]);
                index += 2;
            } else if (strcmp(argv[index], "use-p2p") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                parse_bool_override(&options.use_p2p, argv[index + 1]);
                index += 2;
            } else if (strcmp(argv[index], "stricter-path-scoping") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                parse_bool_override(&options.stricter_path_scoping, argv[index + 1]);
                index += 2;
            } else if (strcmp(argv[index], "include-txt-record") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                parse_bool_override(&options.include_txt_record, argv[index + 1]);
                index += 2;
            } else if (strcmp(argv[index], "sign-results") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                parse_bool_override(&options.sign_results, argv[index + 1]);
                index += 2;
            } else if (strcmp(argv[index], "require-interface") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                options.required_interface_name = argv[index + 1];
                index += 2;
            } else if (strcmp(argv[index], "require-netagent") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                options.required_netagent_uuid = argv[index + 1];
                index += 2;
            } else if (strcmp(argv[index], "require-netagent-class") == 0) {
                if (index + 2 >= argc) {
                    usage(argv[0]);
                }
                options.required_netagent_domain = argv[index + 1];
                options.required_netagent_type = argv[index + 2];
                index += 3;
            } else {
                fprintf(stderr, "unknown browse option: %s\n", argv[index]);
                usage(argv[0]);
            }
        }
        run_appsvc_browser(argv[2],
                           argv[3],
                           (int)seconds,
                           endpoints_only,
                           device_types,
                           has_device_types,
                           browse_scope,
                           has_browse_scope,
                           &options);
        return 0;
    }
    if (strcmp(argv[1], "group-appsvc") == 0) {
        if (argc < 5) {
            usage(argv[0]);
        }
        endpoint = create_appsvc_alias(argv[2], argv[3]);
        nw_endpoint_set_uuid_fn setter =
            (nw_endpoint_set_uuid_fn)lookup("nw_endpoint_set_service_identifier");
        uuid_t service_id;
        parse_uuid_or_die(argv[4], service_id);
        setter(endpoint, service_id);
        int index = 5;
        while (index < argc) {
            apply_appsvc_option(endpoint, &index, argc, argv);
        }

        printf("endpoint.raw=%p\n", endpoint);
        dump_endpoint_dictionary(endpoint, "endpoint");
        run_appsvc_group(endpoint, argv[4]);
        nw_release(endpoint);
        return 0;
    }

    if (strcmp(argv[1], "appsvc") == 0) {
        if (argc < 4) {
            usage(argv[0]);
        }
        endpoint = create_appsvc(argv[2], argv[3]);
        int index = 4;
        while (index < argc) {
            apply_appsvc_option(endpoint, &index, argc, argv);
        }
    } else if (strcmp(argv[1], "appsvc-alias") == 0) {
        if (argc < 4) {
            usage(argv[0]);
        }
        endpoint = create_appsvc_alias(argv[2], argv[3]);
        int index = 4;
        while (index < argc) {
            apply_appsvc_option(endpoint, &index, argc, argv);
        }
    } else if (strcmp(argv[1], "connect-appsvc-alias") == 0) {
        if (argc < 6) {
            usage(argv[0]);
        }
        endpoint = create_appsvc_alias(argv[2], argv[3]);
        int index = 6;
        struct connection_options options = {0};
        char *end = NULL;
        long seconds = strtol(argv[5], &end, 10);
        if (!end || *end != '\0' || seconds < 1 || seconds > 120) {
            fprintf(stderr, "invalid SECONDS: %s\n", argv[5]);
            exit(2);
        }

        nw_endpoint_set_uuid_fn setter =
            (nw_endpoint_set_uuid_fn)lookup("nw_endpoint_set_service_identifier");
        uuid_t service_id;
        parse_uuid_or_die(argv[4], service_id);
        setter(endpoint, service_id);

        while (index < argc) {
            if (strcmp(argv[index], "require-interface") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                options.required_interface_name = argv[index + 1];
                index += 2;
            } else if (strcmp(argv[index], "require-netagent") == 0) {
                if (index + 1 >= argc) {
                    usage(argv[0]);
                }
                options.required_netagent_uuid = argv[index + 1];
                index += 2;
            } else if (strcmp(argv[index], "require-netagent-class") == 0) {
                if (index + 2 >= argc) {
                    usage(argv[0]);
                }
                options.required_netagent_domain = argv[index + 1];
                options.required_netagent_type = argv[index + 2];
                index += 3;
            } else {
                apply_appsvc_option(endpoint, &index, argc, argv);
            }
        }
    } else if (strcmp(argv[1], "bonjour") == 0) {
        if (argc != 5) {
            usage(argv[0]);
        }
        endpoint = create_bonjour(argv[2], argv[3], argv[4]);
    } else {
        usage(argv[0]);
    }

    printf("endpoint.raw=%p\n", endpoint);
    dump_endpoint_dictionary(endpoint, "endpoint");
    dump_string_getter(endpoint, "nw_endpoint_get_application_service_name",
                       "endpoint.application_service_name");
    dump_string_getter(endpoint, "nw_endpoint_get_application_service_alias",
                       "endpoint.application_service_alias");
    dump_string_getter(endpoint, "nw_endpoint_get_device_name", "endpoint.device_name");
    dump_string_getter(endpoint, "nw_endpoint_get_device_id", "endpoint.device_id");

    if (strcmp(argv[1], "connect-appsvc-alias") == 0) {
        struct connection_options options = {0};
        for (int index = 6; index + 1 < argc; index++) {
            if (strcmp(argv[index], "require-interface") == 0) {
                options.required_interface_name = argv[index + 1];
                index++;
            } else if (strcmp(argv[index], "require-netagent") == 0) {
                options.required_netagent_uuid = argv[index + 1];
                index++;
            } else if (strcmp(argv[index], "require-netagent-class") == 0 && index + 2 < argc) {
                options.required_netagent_domain = argv[index + 1];
                options.required_netagent_type = argv[index + 2];
                index += 2;
            }
        }
        run_connection(endpoint, atoi(argv[5]), &options);
    }

    nw_release(endpoint);
    return 0;
}
