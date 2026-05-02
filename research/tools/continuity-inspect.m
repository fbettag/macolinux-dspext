#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <objc/runtime.h>

static NSArray<NSString *> *FrameworkPaths(void) {
    return @[
        @"/System/Library/PrivateFrameworks/CoreUtils.framework/CoreUtils",
        @"/System/Library/PrivateFrameworks/Rapport.framework/Rapport",
        @"/System/Library/PrivateFrameworks/Sharing.framework/Sharing",
        @"/System/Library/PrivateFrameworks/IDS.framework/IDS",
        @"/System/Library/PrivateFrameworks/IDSFoundation.framework/IDSFoundation",
        @"/System/Library/Frameworks/Network.framework/Network"
    ];
}

static void LoadContinuityFrameworks(void) {
    for (NSString *path in FrameworkPaths()) {
        void *handle = dlopen(path.UTF8String, RTLD_NOW | RTLD_LOCAL);
        printf("%-13s %s\n", handle ? "loaded" : "missing", path.UTF8String);
    }
}

static BOOL StringContains(NSString *haystack, NSString *needle) {
    if (!needle || needle.length == 0) {
        return YES;
    }
    return [haystack rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound;
}

static NSData *DataFromProbeArgument(NSString *argument);
static void PrintPairingControllerXPCState(id controller, const char *label);

static NSString *SafeString(id object) {
    if (!object || object == (id)kCFNull) {
        return @"";
    }
    NSString *text = [object description];
    return text ?: @"";
}

static void PrintClassList(NSString *filter) {
    LoadContinuityFrameworks();

    int count = objc_getClassList(NULL, 0);
    Class *classes = (Class *)calloc((size_t)count, sizeof(Class));
    if (!classes) {
        fprintf(stderr, "calloc failed\n");
        return;
    }
    count = objc_getClassList(classes, count);

    NSMutableArray<NSString *> *names = [NSMutableArray array];
    for (int i = 0; i < count; i++) {
        NSString *name = [NSString stringWithUTF8String:class_getName(classes[i])];
        if (StringContains(name, filter)) {
            [names addObject:name];
        }
    }
    free(classes);

    [names sortUsingSelector:@selector(compare:)];
    for (NSString *name in names) {
        puts(name.UTF8String);
    }
}

static void PrintMethods(Class cls, BOOL meta, BOOL includeIMP, NSString *filter) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(meta ? object_getClass(cls) : cls, &count);
    printf("%s methods (%u):\n", meta ? "class" : "instance", count);
    for (unsigned int i = 0; i < count; i++) {
        SEL selector = method_getName(methods[i]);
        const char *types = method_getTypeEncoding(methods[i]);
        NSString *selectorString = [NSString stringWithUTF8String:sel_getName(selector)];
        if (!StringContains(selectorString, filter)) {
            continue;
        }
        if (!includeIMP) {
            printf("  %c[%s %s] %s\n",
                   meta ? '+' : '-',
                   class_getName(cls),
                   sel_getName(selector),
                   types ? types : "");
            continue;
        }
        IMP imp = method_getImplementation(methods[i]);
        Dl_info info = {0};
        const char *image = "";
        uintptr_t offset = 0;
        if (imp && dladdr((const void *)imp, &info) && info.dli_fname && info.dli_fbase) {
            image = info.dli_fname;
            offset = (uintptr_t)imp - (uintptr_t)info.dli_fbase;
        }
        printf("  %c[%s %s] %s imp=%p image=%s",
               meta ? '+' : '-',
               class_getName(cls),
               sel_getName(selector),
               types ? types : "",
               imp,
               image);
        if (offset) {
            printf(" offset=0x%llx", (unsigned long long)offset);
        }
        putchar('\n');
    }
    free(methods);
}

static void PrintProperties(Class cls) {
    unsigned int count = 0;
    objc_property_t *properties = class_copyPropertyList(cls, &count);
    printf("properties (%u):\n", count);
    for (unsigned int i = 0; i < count; i++) {
        const char *name = property_getName(properties[i]);
        const char *attrs = property_getAttributes(properties[i]);
        printf("  %s %s\n", name ? name : "", attrs ? attrs : "");
    }
    free(properties);
}

static void PrintIvars(Class cls) {
    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList(cls, &count);
    printf("ivars (%u):\n", count);
    for (unsigned int i = 0; i < count; i++) {
        const char *name = ivar_getName(ivars[i]);
        const char *type = ivar_getTypeEncoding(ivars[i]);
        printf("  %s %s offset=%td\n", name ? name : "", type ? type : "", ivar_getOffset(ivars[i]));
    }
    free(ivars);
}

static void PrintClassInfo(NSString *className) {
    LoadContinuityFrameworks();

    Class cls = NSClassFromString(className);
    if (!cls) {
        fprintf(stderr, "class not found: %s\n", className.UTF8String);
        return;
    }

    printf("class %s\n", class_getName(cls));
    Class superclass = class_getSuperclass(cls);
    if (superclass) {
        printf("superclass %s\n", class_getName(superclass));
    }
    PrintProperties(cls);
    PrintIvars(cls);
    PrintMethods(cls, NO, NO, nil);
    PrintMethods(cls, YES, NO, nil);
}

static void PrintClassIMPs(NSString *className, NSString *filter) {
    LoadContinuityFrameworks();

    Class cls = NSClassFromString(className);
    if (!cls) {
        fprintf(stderr, "class not found: %s\n", className.UTF8String);
        return;
    }

    printf("class %s\n", class_getName(cls));
    PrintMethods(cls, NO, YES, filter);
    PrintMethods(cls, YES, YES, filter);
}

static void PrintMethodSearch(NSString *filter) {
    LoadContinuityFrameworks();

    int count = objc_getClassList(NULL, 0);
    Class *classes = (Class *)calloc((size_t)count, sizeof(Class));
    if (!classes) {
        fprintf(stderr, "calloc failed\n");
        return;
    }
    count = objc_getClassList(classes, count);

    NSMutableArray<NSString *> *matches = [NSMutableArray array];
    for (int i = 0; i < count; i++) {
        Class cls = classes[i];
        for (int meta = 0; meta < 2; meta++) {
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(meta ? object_getClass(cls) : cls, &methodCount);
            for (unsigned int j = 0; j < methodCount; j++) {
                NSString *selector = [NSString stringWithUTF8String:sel_getName(method_getName(methods[j]))];
                if (!StringContains(selector, filter)) {
                    continue;
                }
                [matches addObject:[NSString stringWithFormat:@"%c[%s %@]",
                                    meta ? '+' : '-',
                                    class_getName(cls),
                                    selector]];
            }
            free(methods);
        }
    }
    free(classes);

    [matches sortUsingSelector:@selector(compare:)];
    for (NSString *match in matches) {
        puts(match.UTF8String);
    }
}

static void PrintProtocolMethods(Protocol *protocol, BOOL required, BOOL instance) {
    unsigned int count = 0;
    struct objc_method_description *methods =
        protocol_copyMethodDescriptionList(protocol, required, instance, &count);
    printf("%s %s methods (%u):\n",
           required ? "required" : "optional",
           instance ? "instance" : "class",
           count);
    for (unsigned int i = 0; i < count; i++) {
        printf("  %c%s %s\n",
               instance ? '-' : '+',
               sel_getName(methods[i].name),
               methods[i].types ?: "");
    }
    free(methods);
}

static void PrintProtocolInfo(NSString *protocolName) {
    LoadContinuityFrameworks();

    Protocol *protocol = objc_getProtocol(protocolName.UTF8String);
    if (!protocol) {
        fprintf(stderr, "protocol not found: %s\n", protocolName.UTF8String);
        return;
    }

    printf("protocol %s\n", protocol_getName(protocol));
    PrintProtocolMethods(protocol, YES, YES);
    PrintProtocolMethods(protocol, NO, YES);
    PrintProtocolMethods(protocol, YES, NO);
    PrintProtocolMethods(protocol, NO, NO);
}

static NSDictionary *KeychainQuery(CFTypeRef secClass) {
    return @{
        (__bridge id)kSecClass: (__bridge id)secClass,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecUseDataProtectionKeychain: @YES,
    };
}

static BOOL AttributeLooksRelevant(NSDictionary *item) {
    NSArray *needles = @[
        @"rapport",
        @"pair",
        @"paired",
        @"continuity",
        @"coreutils",
        @"sharing",
        @"appleid",
        @"ids",
        @"remote display",
        @"remotecontrol",
        @"com.apple.rapport",
        @"com.apple.coreutils",
        @"com.apple.continuity",
    ];

    NSMutableString *joined = [NSMutableString string];
    for (id key in item) {
        [joined appendString:SafeString(key)];
        [joined appendString:@"="];
        [joined appendString:SafeString(item[key])];
        [joined appendString:@"\n"];
    }

    for (NSString *needle in needles) {
        if (StringContains(joined, needle)) {
            return YES;
        }
    }
    return NO;
}

static NSString *RedactedLength(id object) {
    if (!object || object == (id)kCFNull) {
        return @"";
    }
    if ([object isKindOfClass:[NSData class]]) {
        return [NSString stringWithFormat:@"<data:%lu>", (unsigned long)[(NSData *)object length]];
    }
    NSString *text = SafeString(object);
    if (text.length == 0) {
        return @"";
    }
    return [NSString stringWithFormat:@"<string:%lu>", (unsigned long)text.length];
}

static void PrintKeychainSummary(void) {
    NSArray<NSDictionary *> *queries = @[
        @{@"name": @"generic-password", @"query": KeychainQuery(kSecClassGenericPassword)},
        @{@"name": @"key", @"query": KeychainQuery(kSecClassKey)},
        @{@"name": @"certificate", @"query": KeychainQuery(kSecClassCertificate)},
        @{@"name": @"identity", @"query": KeychainQuery(kSecClassIdentity)},
    ];

    NSArray *safeKeys = @[
        (__bridge id)kSecAttrAccessGroup,
        (__bridge id)kSecAttrAccount,
        (__bridge id)kSecAttrApplicationLabel,
        (__bridge id)kSecAttrApplicationTag,
        (__bridge id)kSecAttrDescription,
        (__bridge id)kSecAttrKeyClass,
        (__bridge id)kSecAttrKeyType,
        (__bridge id)kSecAttrLabel,
        (__bridge id)kSecAttrService,
        (__bridge id)kSecAttrSynchronizable,
    ];

    for (NSDictionary *entry in queries) {
        NSString *name = entry[@"name"];
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)entry[@"query"], &result);
        if (status == errSecItemNotFound) {
            printf("%s: 0 items\n", name.UTF8String);
            continue;
        }
        if (status != errSecSuccess) {
            printf("%s: SecItemCopyMatching failed: %d\n", name.UTF8String, (int)status);
            continue;
        }

        NSArray *items = CFBridgingRelease(result);
        if (![items isKindOfClass:[NSArray class]]) {
            printf("%s: unexpected result type\n", name.UTF8String);
            continue;
        }

        NSUInteger relevant = 0;
        for (NSDictionary *item in items) {
            if (AttributeLooksRelevant(item)) {
                relevant++;
            }
        }
        printf("%s: %lu items, %lu relevant-looking metadata records\n",
               name.UTF8String,
               (unsigned long)items.count,
               (unsigned long)relevant);

        NSUInteger index = 0;
        for (NSDictionary *item in items) {
            if (!AttributeLooksRelevant(item)) {
                continue;
            }
            printf("  item %lu\n", (unsigned long)index++);
            for (id key in safeKeys) {
                id value = item[key];
                if (value) {
                    printf("    %s: %s\n", SafeString(key).UTF8String, RedactedLength(value).UTF8String);
                }
            }
        }
    }
}

static NSString *DescribeData(id object) {
    if ([object isKindOfClass:[NSData class]]) {
        return [NSString stringWithFormat:@"data:%lu", (unsigned long)[(NSData *)object length]];
    }
    return object ? NSStringFromClass([object class]) : @"nil";
}

static NSString *DescribeString(id object) {
    if ([object isKindOfClass:[NSString class]]) {
        return [NSString stringWithFormat:@"string:%lu", (unsigned long)[(NSString *)object length]];
    }
    if ([object isKindOfClass:[NSUUID class]]) {
        return @"uuid";
    }
    return object ? NSStringFromClass([object class]) : @"nil";
}

static NSString *HexString(NSData *data, NSUInteger maxBytes) {
    if (!data) {
        return @"";
    }
    const uint8_t *bytes = data.bytes;
    NSUInteger length = MIN(data.length, maxBytes);
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (NSUInteger i = 0; i < length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    if (data.length > maxBytes) {
        [hex appendFormat:@"...(+%lu bytes)", (unsigned long)(data.length - maxBytes)];
    }
    return hex;
}

static void PrintCFObjectShape(CFTypeRef object, const char *label) {
    if (!object) {
        printf("%s: nil\n", label);
        return;
    }
    CFStringRef description = CFCopyDescription(object);
    char buffer[4096] = {0};
    Boolean copied = description &&
        CFStringGetCString(description, buffer, sizeof(buffer), kCFStringEncodingUTF8);
    printf("%s: cfType=%lu class=%s desc=%s\n",
           label,
           CFGetTypeID(object),
           object_getClassName((__bridge id)object),
           copied ? buffer : "(description unavailable)");
    if (CFGetTypeID(object) == CFDataGetTypeID()) {
        NSData *data = (__bridge NSData *)object;
        printf("%s: data_len=%lu hex=%s\n",
               label,
               (unsigned long)data.length,
               HexString(data, 128).UTF8String);
    }
    if (description) {
        CFRelease(description);
    }
}

static void ProbeSecuritySPAKE(NSString *clientIdentity, NSString *serverIdentity, unsigned short scheme) {
    LoadContinuityFrameworks();

    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    printf("Security handle: %p\n", security);
    NSArray<NSString *> *symbols = @[
        @"sec_identity_create_client_SPAKE2PLUSV1_identity",
        @"sec_identity_create_server_SPAKE2PLUSV1_identity",
        @"sec_identity_copy_SPAKE2PLUSV1_client_identity",
        @"sec_identity_copy_SPAKE2PLUSV1_server_identity",
        @"sec_identity_copy_SPAKE2PLUSV1_context",
        @"sec_identity_copy_SPAKE2PLUSV1_registration_record",
        @"sec_identity_copy_SPAKE2PLUSV1_client_password_verifier",
        @"sec_identity_copy_SPAKE2PLUSV1_server_password_verifier",
        @"sec_protocol_options_set_pake_challenge_block",
        @"sec_protocol_metadata_get_tls_pake_offered",
        @"sec_protocol_metadata_get_tls_negotiated_pake",
    ];
    for (NSString *symbol in symbols) {
        printf("%-60s %p\n", symbol.UTF8String, dlsym(RTLD_DEFAULT, symbol.UTF8String));
    }

    Class offeredClass = NSClassFromString(@"SecOfferedPAKEIdentity");
    printf("SecOfferedPAKEIdentity class: %s\n", offeredClass ? class_getName(offeredClass) : "nil");
    if (!offeredClass) {
        return;
    }
    PrintMethods(offeredClass, NO, NO, nil);
    id allocated = ((id (*)(id, SEL))objc_msgSend)(offeredClass, @selector(alloc));
    SEL initSelector = NSSelectorFromString(@"initWithClientIdentity:::");
    id offered = ((id (*)(id, SEL, id, id, unsigned short))objc_msgSend)(
        allocated,
        initSelector,
        clientIdentity ?: @"",
        serverIdentity ?: @"",
        scheme);
    id client = ((id (*)(id, SEL))objc_msgSend)(offered, NSSelectorFromString(@"client_identity"));
    id server = ((id (*)(id, SEL))objc_msgSend)(offered, NSSelectorFromString(@"server_identity"));
    unsigned short actualScheme =
        ((unsigned short (*)(id, SEL))objc_msgSend)(offered, NSSelectorFromString(@"pake_scheme"));
    printf("offered: %s client=%s server=%s scheme=%u\n",
           [[offered description] UTF8String],
           [SafeString(client) UTF8String],
           [SafeString(server) UTF8String],
           actualScheme);
    PrintCFObjectShape((__bridge CFTypeRef)offered, "offered");
}

static dispatch_data_t DispatchDataFromNSData(NSData *data) {
    if (!data) {
        return nil;
    }
    void *buffer = malloc(data.length);
    if (!buffer && data.length > 0) {
        return nil;
    }
    if (data.length > 0) {
        memcpy(buffer, data.bytes, data.length);
    }
    return dispatch_data_create(buffer, data.length, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), DISPATCH_DATA_DESTRUCTOR_FREE);
}

static void PrintDispatchDataObject(id object, const char *label) {
    if (!object) {
        printf("%s: nil\n", label);
        return;
    }

    const char *className = object_getClassName(object);
    printf("%s: class=%s desc=%s\n",
           label,
           className ? className : "(unknown)",
           [[object description] UTF8String]);

    if (![object conformsToProtocol:@protocol(OS_dispatch_data)]) {
        return;
    }

    dispatch_data_t data = (dispatch_data_t)object;
    size_t size = dispatch_data_get_size(data);
    const void *buffer = NULL;
    size_t mappedSize = 0;
    dispatch_data_t mapped = dispatch_data_create_map(data, &buffer, &mappedSize);
    NSData *bytes = buffer && mappedSize > 0 ? [NSData dataWithBytes:buffer length:mappedSize] : [NSData data];
    printf("%s: dispatch_len=%zu hex=%s\n", label, size, HexString(bytes, 256).UTF8String);
    (void)mapped;
}

static void PrintSPAKEIdentityFields(id identity) {
    NSArray<NSString *> *symbols = @[
        @"sec_identity_copy_SPAKE2PLUSV1_context",
        @"sec_identity_copy_SPAKE2PLUSV1_client_identity",
        @"sec_identity_copy_SPAKE2PLUSV1_server_identity",
        @"sec_identity_copy_SPAKE2PLUSV1_client_password_verifier",
        @"sec_identity_copy_SPAKE2PLUSV1_server_password_verifier",
        @"sec_identity_copy_SPAKE2PLUSV1_registration_record",
    ];
    for (NSString *symbol in symbols) {
        id (*copyFn)(id) = (id (*)(id))dlsym(RTLD_DEFAULT, symbol.UTF8String);
        if (!copyFn) {
            printf("%s unavailable\n", symbol.UTF8String);
            continue;
        }
        id value = copyFn(identity);
        PrintDispatchDataObject(value, symbol.UTF8String);
    }
}

static void CreateClientSPAKEIdentity(NSString *contextArg,
                                      NSString *clientIdentityArg,
                                      NSString *serverIdentityArg,
                                      NSString *passwordArg) {
    LoadContinuityFrameworks();

    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    printf("Security handle: %p\n", security);

    typedef id (*CreateClientFn)(id, dispatch_data_t, dispatch_data_t, dispatch_data_t, int);
    CreateClientFn createClient = (CreateClientFn)dlsym(RTLD_DEFAULT, "sec_identity_create_client_SPAKE2PLUSV1_identity");
    if (!createClient) {
        puts("sec_identity_create_client_SPAKE2PLUSV1_identity unavailable");
        return;
    }

    NSData *contextBytes = DataFromProbeArgument(contextArg ?: @"");
    NSData *clientIdentityBytes = DataFromProbeArgument(clientIdentityArg ?: @"");
    NSData *serverIdentityBytes = DataFromProbeArgument(serverIdentityArg ?: @"");
    NSData *passwordBytes = DataFromProbeArgument(passwordArg ?: @"");

    dispatch_data_t contextData = DispatchDataFromNSData(contextBytes);
    dispatch_data_t clientIdentityData = DispatchDataFromNSData(clientIdentityBytes);
    dispatch_data_t serverIdentityData = DispatchDataFromNSData(serverIdentityBytes);
    dispatch_data_t passwordData = DispatchDataFromNSData(passwordBytes);

    PrintDispatchDataObject(contextData, "input.context");
    PrintDispatchDataObject(clientIdentityData, "input.client_identity");
    PrintDispatchDataObject(serverIdentityData, "input.server_identity");
    PrintDispatchDataObject(passwordData, "input.password");

    id identity = createClient(contextData, clientIdentityData, serverIdentityData, passwordData, 0);
    printf("client_identity_object: %s\n", identity ? [[identity description] UTF8String] : "nil");
    PrintSPAKEIdentityFields(identity);
}

static void CreateServerSPAKEIdentity(NSString *contextArg,
                                      NSString *clientIdentityArg,
                                      NSString *serverIdentityArg,
                                      NSString *serverPasswordVerifierArg,
                                      NSString *registrationRecordArg) {
    LoadContinuityFrameworks();

    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    printf("Security handle: %p\n", security);

    typedef id (*CreateServerFn)(id, id, id, dispatch_data_t, dispatch_data_t);
    CreateServerFn createServer = (CreateServerFn)dlsym(RTLD_DEFAULT, "sec_identity_create_server_SPAKE2PLUSV1_identity");
    if (!createServer) {
        puts("sec_identity_create_server_SPAKE2PLUSV1_identity unavailable");
        return;
    }

    NSData *contextBytes = DataFromProbeArgument(contextArg ?: @"");
    NSData *clientIdentityBytes = DataFromProbeArgument(clientIdentityArg ?: @"");
    NSData *serverIdentityBytes = DataFromProbeArgument(serverIdentityArg ?: @"");
    NSData *serverPasswordVerifierBytes = DataFromProbeArgument(serverPasswordVerifierArg ?: @"");
    NSData *registrationRecordBytes = DataFromProbeArgument(registrationRecordArg ?: @"");

    dispatch_data_t contextData = DispatchDataFromNSData(contextBytes);
    dispatch_data_t clientIdentityData = DispatchDataFromNSData(clientIdentityBytes);
    dispatch_data_t serverIdentityData = DispatchDataFromNSData(serverIdentityBytes);
    dispatch_data_t serverPasswordVerifierData = DispatchDataFromNSData(serverPasswordVerifierBytes);
    dispatch_data_t registrationRecordData = DispatchDataFromNSData(registrationRecordBytes);

    PrintDispatchDataObject(contextData, "input.context");
    PrintDispatchDataObject(clientIdentityData, "input.client_identity");
    PrintDispatchDataObject(serverIdentityData, "input.server_identity");
    PrintDispatchDataObject(serverPasswordVerifierData, "input.server_password_verifier");
    PrintDispatchDataObject(registrationRecordData, "input.registration_record");

    id identity = createServer(contextData,
                               clientIdentityData,
                               serverIdentityData,
                               serverPasswordVerifierData,
                               registrationRecordData);
    printf("server_identity_object: %s\n", identity ? [[identity description] UTF8String] : "nil");
    PrintSPAKEIdentityFields(identity);
}

static const char *NetworkBrowserStateName(nw_browser_state_t state) {
    switch (state) {
        case nw_browser_state_invalid: return "invalid";
        case nw_browser_state_ready: return "ready";
        case nw_browser_state_failed: return "failed";
        case nw_browser_state_cancelled: return "cancelled";
        case nw_browser_state_waiting: return "waiting";
        default: return "unknown";
    }
}

static const char *NetworkListenerStateName(nw_listener_state_t state) {
    switch (state) {
        case nw_listener_state_invalid: return "invalid";
        case nw_listener_state_waiting: return "waiting";
        case nw_listener_state_ready: return "ready";
        case nw_listener_state_failed: return "failed";
        case nw_listener_state_cancelled: return "cancelled";
        default: return "unknown";
    }
}

static NSData *DataFromHexString(NSString *hex, NSError **errorOut) {
    NSMutableString *cleaned = [NSMutableString stringWithCapacity:hex.length];
    NSCharacterSet *skip = [NSCharacterSet characterSetWithCharactersInString:@" \n\r\t:-"];
    for (NSUInteger i = 0; i < hex.length; i++) {
        unichar ch = [hex characterAtIndex:i];
        if (![skip characterIsMember:ch]) {
            [cleaned appendFormat:@"%C", ch];
        }
    }
    if (cleaned.length % 2 != 0) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"continuity-inspect"
                                            code:1
                                        userInfo:@{NSLocalizedDescriptionKey: @"hex string has odd length"}];
        }
        return nil;
    }

    NSMutableData *data = [NSMutableData dataWithCapacity:cleaned.length / 2];
    for (NSUInteger i = 0; i < cleaned.length; i += 2) {
        NSString *pair = [cleaned substringWithRange:NSMakeRange(i, 2)];
        unsigned int byte = 0;
        NSScanner *scanner = [NSScanner scannerWithString:pair];
        if (![scanner scanHexInt:&byte] || byte > 0xff) {
            if (errorOut) {
                *errorOut = [NSError errorWithDomain:@"continuity-inspect"
                                                code:2
                                            userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"invalid hex byte at offset %lu", (unsigned long)i]}];
            }
            return nil;
        }
        uint8_t value = (uint8_t)byte;
        [data appendBytes:&value length:1];
    }
    return data;
}

static NSDictionary *LoadJSONDictionary(NSString *path);
static id BuildPairedPeerFromJSON(NSDictionary *json);

static id JSONValueFromArgument(NSString *argument) {
    if (!argument || argument.length == 0 || [argument isEqualToString:@"-"]) {
        return @{};
    }

    NSData *data = nil;
    if ([argument hasPrefix:@"@"]) {
        NSString *path = [argument substringFromIndex:1];
        data = [NSData dataWithContentsOfFile:path];
        if (!data) {
            fprintf(stderr, "failed to read JSON argument file: %s\n", path.UTF8String);
            return nil;
        }
    } else {
        data = [argument dataUsingEncoding:NSUTF8StringEncoding];
    }

    NSError *error = nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error) {
        fprintf(stderr, "failed to parse JSON argument: %s\n", error.description.UTF8String);
        return nil;
    }
    return object ?: @{};
}

static BOOL WaitForSemaphore(dispatch_semaphore_t sem, NSTimeInterval timeout) {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) != 0) {
        if ([deadline timeIntervalSinceNow] <= 0) {
            return NO;
        }
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    return YES;
}

static id SafeValueForKey(id object, NSString *key) {
    if (!object) {
        return nil;
    }
    @try {
        return [object valueForKey:key];
    } @catch (NSException *exception) {
        return nil;
    }
}

static BOOL ReadBoolSelector(id object, SEL selector, BOOL *valueOut) {
    if (!object || ![object respondsToSelector:selector]) {
        return NO;
    }
    typedef BOOL (*BoolFn)(id, SEL);
    BoolFn fn = (BoolFn)[object methodForSelector:selector];
    *valueOut = fn(object, selector);
    return YES;
}

static NSString *AuthTypeName(NSUInteger type) {
    NSDictionary<NSNumber *, NSString *> *names = @{
        @0: @"Unknown",
        @1: @"Siri",
        @2: @"NanoWallet",
        @3: @"MacUnlockPhonePairing",
        @4: @"MacUnlockPhone",
        @5: @"MacApprovePhone",
        @6: @"Registration",
        @7: @"GuestModeUnlockPairing",
        @8: @"GuestModeUnlock",
        @9: @"VisionUnlockiOSPairing",
        @10: @"VisionUnlockiOS",
        @11: @"VisionApproveiOS",
    };
    return names[@(type)] ?: @"";
}

static id NewAuthenticationManager(void) {
    Class managerClass = NSClassFromString(@"SFAuthenticationManager");
    if (!managerClass) {
        return nil;
    }

    id manager = [managerClass alloc];
    SEL initWithQueueSelector = @selector(initWithQueue:);
    if ([manager respondsToSelector:initWithQueueSelector]) {
        typedef id (*InitWithQueueFn)(id, SEL, dispatch_queue_t);
        InitWithQueueFn fn = (InitWithQueueFn)[manager methodForSelector:initWithQueueSelector];
        return fn(manager, initWithQueueSelector, dispatch_get_main_queue());
    }
    return [manager init];
}

static void PrintAuthenticationDeviceShape(id device, NSUInteger index) {
    id idsDeviceID = SafeValueForKey(device, @"idsDeviceID");
    id modelDescription = SafeValueForKey(device, @"modelDescription");
    BOOL enabledAsKey = NO;
    BOOL enabledAsLock = NO;
    BOOL bluetoothCloudPaired = NO;
    BOOL hasKey = ReadBoolSelector(device, @selector(enabledAsKey), &enabledAsKey);
    BOOL hasLock = ReadBoolSelector(device, @selector(enabledAsLock), &enabledAsLock);
    BOOL hasCloudPaired = ReadBoolSelector(device, @selector(bluetoothCloudPaired), &bluetoothCloudPaired);

    printf("      device %lu:\n", (unsigned long)index);
    printf("        class: %s\n", class_getName([device class]));
    printf("        idsDeviceID: %s\n", DescribeString(idsDeviceID).UTF8String);
    printf("        modelDescription: %s\n", DescribeString(modelDescription).UTF8String);
    if (hasKey) {
        printf("        enabledAsKey: %s\n", enabledAsKey ? "yes" : "no");
    }
    if (hasLock) {
        printf("        enabledAsLock: %s\n", enabledAsLock ? "yes" : "no");
    }
    if (hasCloudPaired) {
        printf("        bluetoothCloudPaired: %s\n", bluetoothCloudPaired ? "yes" : "no");
    }
}

static void PrintAuthenticationDeviceList(NSString *label, NSArray *devices, NSError *error) {
    if (error) {
        printf("    %s error: %s\n", label.UTF8String, error.description.UTF8String);
        return;
    }
    printf("    %s devices: %lu\n", label.UTF8String, (unsigned long)devices.count);
    NSUInteger index = 0;
    for (id device in devices) {
        PrintAuthenticationDeviceShape(device, index++);
    }
}

static void ProbeAuthenticationTypes(NSUInteger maxType) {
    LoadContinuityFrameworks();

    id manager = NewAuthenticationManager();
    if (!manager) {
        fprintf(stderr, "SFAuthenticationManager not found\n");
        return;
    }

    SEL supportedSelector = @selector(isSupportedForType:);
    SEL enabledSelector = @selector(isEnabledForType:);
    SEL candidatesSelector = @selector(listCandidateDevicesForType:completionHandler:);
    SEL eligibleSelector = @selector(listEligibleDevicesForType:completionHandler:);

    for (NSUInteger type = 0; type <= maxType; type++) {
        BOOL supported = NO;
        BOOL enabled = NO;
        BOOL hasSupported = NO;
        BOOL hasEnabled = NO;

        if ([manager respondsToSelector:supportedSelector]) {
            typedef BOOL (*BoolTypeFn)(id, SEL, NSUInteger);
            BoolTypeFn fn = (BoolTypeFn)[manager methodForSelector:supportedSelector];
            supported = fn(manager, supportedSelector, type);
            hasSupported = YES;
        }
        if ([manager respondsToSelector:enabledSelector]) {
            typedef BOOL (*BoolTypeFn)(id, SEL, NSUInteger);
            BoolTypeFn fn = (BoolTypeFn)[manager methodForSelector:enabledSelector];
            enabled = fn(manager, enabledSelector, type);
            hasEnabled = YES;
        }

        NSString *name = AuthTypeName(type);
        printf("type %lu%s%s\n",
               (unsigned long)type,
               name.length ? " " : "",
               name.length ? name.UTF8String : "");
        if (hasSupported) {
            printf("  supported: %s\n", supported ? "yes" : "no");
        } else {
            puts("  supported: method unavailable");
        }
        if (hasEnabled) {
            printf("  enabled: %s\n", enabled ? "yes" : "no");
        } else {
            puts("  enabled: method unavailable");
        }

        if ([manager respondsToSelector:candidatesSelector]) {
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            typedef void (*ListFn)(id, SEL, NSUInteger, void (^)(NSArray *, NSError *));
            ListFn fn = (ListFn)[manager methodForSelector:candidatesSelector];
            fn(manager, candidatesSelector, type, ^(NSArray *devices, NSError *error) {
                PrintAuthenticationDeviceList(@"candidate", devices, error);
                dispatch_semaphore_signal(sem);
            });
            if (!WaitForSemaphore(sem, 3.0)) {
                puts("    candidate timeout");
            }
        }

        if ([manager respondsToSelector:eligibleSelector]) {
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            typedef void (*ListFn)(id, SEL, NSUInteger, void (^)(NSArray *, NSError *));
            ListFn fn = (ListFn)[manager methodForSelector:eligibleSelector];
            fn(manager, eligibleSelector, type, ^(NSArray *devices, NSError *error) {
                PrintAuthenticationDeviceList(@"eligible", devices, error);
                dispatch_semaphore_signal(sem);
            });
            if (!WaitForSemaphore(sem, 3.0)) {
                puts("    eligible timeout");
            }
        }
    }
}

static void ProbeRPPairingListen(NSTimeInterval seconds, BOOL uiVisible) {
    LoadContinuityFrameworks();

    Class controllerClass = NSClassFromString(@"Rapport.RPPairingReceiverController");
    if (!controllerClass) {
        fprintf(stderr, "Rapport.RPPairingReceiverController not found\n");
        return;
    }

    id controller = [controllerClass alloc];
    SEL initWithQueueSelector = @selector(initWithQueue:);
    if ([controller respondsToSelector:initWithQueueSelector]) {
        typedef id (*InitWithQueueFn)(id, SEL, dispatch_queue_t);
        InitWithQueueFn fn = (InitWithQueueFn)[controller methodForSelector:initWithQueueSelector];
        controller = fn(controller, initWithQueueSelector, dispatch_get_main_queue());
    } else {
        controller = [controller init];
    }

    if (!controller) {
        fprintf(stderr, "failed to create RPPairingReceiverController\n");
        return;
    }

    __block NSUInteger eventCount = 0;
    id handler = ^(id value) {
        eventCount++;
        printf("pairing event %lu: class=%s description=%s\n",
               (unsigned long)eventCount,
               value ? class_getName([value class]) : "nil",
               RedactedLength(value).UTF8String);
    };

    SEL setHandlerSelector = @selector(setPairingValueUpdatedHandler:);
    if ([controller respondsToSelector:setHandlerSelector]) {
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[controller methodForSelector:setHandlerSelector];
        fn(controller, setHandlerSelector, [handler copy]);
    } else {
        puts("pairingValueUpdatedHandler setter unavailable");
    }

    SEL setVisibleSelector = @selector(setPairingValueUIVisible:);
    typedef void (*SetBoolFn)(id, SEL, BOOL);
    SetBoolFn setVisible = NULL;
    if ([controller respondsToSelector:setVisibleSelector]) {
        setVisible = (SetBoolFn)[controller methodForSelector:setVisibleSelector];
        setVisible(controller, setVisibleSelector, uiVisible);
        printf("pairing UI visible: %s\n", uiVisible ? "yes" : "no");
    } else {
        puts("pairingValueUIVisible setter unavailable");
    }

    SEL startSelector = @selector(start);
    if (![controller respondsToSelector:startSelector]) {
        puts("start method unavailable");
        return;
    }
    typedef void (*VoidFn)(id, SEL);
    VoidFn start = (VoidFn)[controller methodForSelector:startSelector];
    start(controller, startSelector);
    PrintPairingControllerXPCState(controller, "pairing");
    if (setVisible) {
        setVisible(controller, setVisibleSelector, uiVisible);
    }

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
    while ([deadline timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }

    SEL stopSelector = @selector(stop);
    if ([controller respondsToSelector:stopSelector]) {
        VoidFn stop = (VoidFn)[controller methodForSelector:stopSelector];
        stop(controller, stopSelector);
    }

    printf("pairing events observed: %lu\n", (unsigned long)eventCount);
}

static void ProbeRemoteDisplayPairingServer(NSTimeInterval seconds) {
    LoadContinuityFrameworks();

    Class serverClass = NSClassFromString(@"RPRemoteDisplayServer");
    if (!serverClass) {
        fprintf(stderr, "RPRemoteDisplayServer not found\n");
        return;
    }

    id server = [[serverClass alloc] init];
    if (!server) {
        fprintf(stderr, "failed to create RPRemoteDisplayServer\n");
        return;
    }

    SEL setQueueSelector = @selector(setDispatchQueue:);
    if ([server respondsToSelector:setQueueSelector]) {
        typedef void (*SetQueueFn)(id, SEL, dispatch_queue_t);
        SetQueueFn fn = (SetQueueFn)[server methodForSelector:setQueueSelector];
        fn(server, setQueueSelector, dispatch_get_main_queue());
    }

    SEL setShowPasswordSelector = @selector(setShowPasswordHandler:);
    if ([server respondsToSelector:setShowPasswordSelector]) {
        id handler = ^(id password, unsigned int flags) {
            printf("remote display show password: %s flags=0x%x\n",
                   RedactedLength(password).UTF8String,
                   flags);
        };
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[server methodForSelector:setShowPasswordSelector];
        fn(server, setShowPasswordSelector, [handler copy]);
    }

    SEL setHidePasswordSelector = @selector(setHidePasswordHandler:);
    if ([server respondsToSelector:setHidePasswordSelector]) {
        id handler = ^(void) {
            puts("remote display hide password");
        };
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[server methodForSelector:setHidePasswordSelector];
        fn(server, setHidePasswordSelector, [handler copy]);
    }

    dispatch_semaphore_t activateSem = dispatch_semaphore_create(0);
    SEL activateSelector = @selector(activateWithCompletion:);
    if ([server respondsToSelector:activateSelector]) {
        id completion = ^(NSError *error) {
            if (error) {
                printf("remote display activate error: %s\n", error.description.UTF8String);
            } else {
                puts("remote display activated");
            }
            dispatch_semaphore_signal(activateSem);
        };
        typedef void (*CompletionFn)(id, SEL, id);
        CompletionFn fn = (CompletionFn)[server methodForSelector:activateSelector];
        fn(server, activateSelector, [completion copy]);
        if (!WaitForSemaphore(activateSem, 5.0)) {
            puts("remote display activate timeout");
        }
    }

    dispatch_semaphore_t startSem = dispatch_semaphore_create(0);
    SEL startSelector = @selector(startPairingServerWithCompletion:);
    if (![server respondsToSelector:startSelector]) {
        puts("startPairingServerWithCompletion: unavailable");
        return;
    }
    id startCompletion = ^(NSError *error) {
        if (error) {
            printf("remote display pairing server start error: %s\n", error.description.UTF8String);
        } else {
            puts("remote display pairing server started");
        }
        dispatch_semaphore_signal(startSem);
    };
    typedef void (*CompletionFn)(id, SEL, id);
    CompletionFn start = (CompletionFn)[server methodForSelector:startSelector];
    start(server, startSelector, [startCompletion copy]);
    if (!WaitForSemaphore(startSem, 5.0)) {
        puts("remote display pairing server start timeout");
    }

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
    while ([deadline timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }

    SEL stopSelector = @selector(stopPairingServer);
    if ([server respondsToSelector:stopSelector]) {
        typedef void (*VoidFn)(id, SEL);
        VoidFn stop = (VoidFn)[server methodForSelector:stopSelector];
        stop(server, stopSelector);
        puts("remote display pairing server stopped");
    }

    SEL invalidateSelector = @selector(invalidate);
    if ([server respondsToSelector:invalidateSelector]) {
        typedef void (*VoidFn)(id, SEL);
        VoidFn invalidate = (VoidFn)[server methodForSelector:invalidateSelector];
        invalidate(server, invalidateSelector);
    }
}

static void PrintPairingIdentityShape(id identity) {
    if (!identity) {
        puts("pairing identity: nil");
        return;
    }

    id identifier = [identity respondsToSelector:@selector(identifier)] ? [identity performSelector:@selector(identifier)] : nil;
    id publicKey = [identity respondsToSelector:@selector(publicKey)] ? [identity performSelector:@selector(publicKey)] : nil;
    id secretKey = [identity respondsToSelector:@selector(secretKey)] ? [identity performSelector:@selector(secretKey)] : nil;
    id altIRK = [identity respondsToSelector:@selector(altIRK)] ? [identity performSelector:@selector(altIRK)] : nil;

    printf("pairing identity:\n");
    printf("  class: %s\n", class_getName([identity class]));
    printf("  identifier: %s\n", DescribeString(identifier).UTF8String);
    printf("  publicKey: %s\n", DescribeData(publicKey).UTF8String);
    printf("  secretKey: %s\n", DescribeData(secretKey).UTF8String);
    printf("  altIRK: %s\n", DescribeData(altIRK).UTF8String);
}

static void PrintRPIdentityShape(id identity) {
    if (!identity) {
        puts("rpidentity: nil");
        return;
    }

    id identifier = [identity respondsToSelector:@selector(identifier)] ? [identity performSelector:@selector(identifier)] : nil;
    id name = [identity respondsToSelector:@selector(name)] ? [identity performSelector:@selector(name)] : nil;
    id model = [identity respondsToSelector:@selector(model)] ? [identity performSelector:@selector(model)] : nil;
    id edPKData = [identity respondsToSelector:@selector(edPKData)] ? [identity performSelector:@selector(edPKData)] : nil;
    id accountID = [identity respondsToSelector:@selector(accountID)] ? [identity performSelector:@selector(accountID)] : nil;
    id accountAltDSID = [identity respondsToSelector:@selector(accountAltDSID)] ? [identity performSelector:@selector(accountAltDSID)] : nil;
    id idsDeviceID = [identity respondsToSelector:@selector(idsDeviceID)] ? [identity performSelector:@selector(idsDeviceID)] : nil;
    id acl = [identity respondsToSelector:@selector(acl)] ? [identity performSelector:@selector(acl)] : nil;
    int type = -1;
    if ([identity respondsToSelector:@selector(type)]) {
        typedef int (*IntGetterFn)(id, SEL);
        IntGetterFn fn = (IntGetterFn)[identity methodForSelector:@selector(type)];
        type = fn(identity, @selector(type));
    }
    int source = -1;
    if ([identity respondsToSelector:@selector(source)]) {
        typedef int (*IntGetterFn)(id, SEL);
        IntGetterFn fn = (IntGetterFn)[identity methodForSelector:@selector(source)];
        source = fn(identity, @selector(source));
    }
    uint64_t featureFlags = 0;
    if ([identity respondsToSelector:@selector(featureFlags)]) {
        typedef uint64_t (*FeatureFlagsFn)(id, SEL);
        FeatureFlagsFn fn = (FeatureFlagsFn)[identity methodForSelector:@selector(featureFlags)];
        featureFlags = fn(identity, @selector(featureFlags));
    }

    printf("  class: %s\n", class_getName([identity class]));
    printf("  description: %s\n", SafeString(identity).UTF8String);
    printf("  type: %d\n", type);
    printf("  source: %d\n", source);
    printf("  featureFlags: 0x%llx\n", (unsigned long long)featureFlags);
    printf("  identifier: %s\n", DescribeString(identifier).UTF8String);
    printf("  name: %s\n", DescribeString(name).UTF8String);
    printf("  model: %s\n", DescribeString(model).UTF8String);
    printf("  edPKData: %s\n", DescribeData(edPKData).UTF8String);
    printf("  accountID: %s\n", DescribeString(accountID).UTF8String);
    printf("  accountAltDSID: %s\n", DescribeString(accountAltDSID).UTF8String);
    printf("  idsDeviceID: %s\n", DescribeString(idsDeviceID).UTF8String);
    if ([acl isKindOfClass:[NSDictionary class]]) {
        printf("  acl keys: %lu\n", (unsigned long)[(NSDictionary *)acl count]);
    } else {
        printf("  acl: %s\n", acl ? class_getName([acl class]) : "nil");
    }
}

static void PrintPeerShape(id peer, NSUInteger index) {
    id identifier = [peer respondsToSelector:@selector(identifier)] ? [peer performSelector:@selector(identifier)] : nil;
    id identifierStr = [peer respondsToSelector:@selector(identifierStr)] ? [peer performSelector:@selector(identifierStr)] : nil;
    id label = [peer respondsToSelector:@selector(label)] ? [peer performSelector:@selector(label)] : nil;
    id model = [peer respondsToSelector:@selector(model)] ? [peer performSelector:@selector(model)] : nil;
    id name = [peer respondsToSelector:@selector(name)] ? [peer performSelector:@selector(name)] : nil;
    id publicKey = [peer respondsToSelector:@selector(publicKey)] ? [peer performSelector:@selector(publicKey)] : nil;
    id altIRK = [peer respondsToSelector:@selector(altIRK)] ? [peer performSelector:@selector(altIRK)] : nil;
    id info = [peer respondsToSelector:@selector(info)] ? [peer performSelector:@selector(info)] : nil;
    id acl = [peer respondsToSelector:@selector(acl)] ? [peer performSelector:@selector(acl)] : nil;

    printf("  peer %lu:\n", (unsigned long)index);
    printf("    class: %s\n", class_getName([peer class]));
    printf("    identifier: %s\n", DescribeString(identifier).UTF8String);
    printf("    identifierStr: %s\n", DescribeString(identifierStr).UTF8String);
    printf("    label: %s\n", DescribeString(label).UTF8String);
    printf("    model: %s\n", DescribeString(model).UTF8String);
    printf("    name: %s\n", DescribeString(name).UTF8String);
    printf("    publicKey: %s\n", DescribeData(publicKey).UTF8String);
    printf("    altIRK: %s\n", DescribeData(altIRK).UTF8String);
    if ([info isKindOfClass:[NSDictionary class]]) {
        printf("    info keys: %lu\n", (unsigned long)[(NSDictionary *)info count]);
        for (id key in [(NSDictionary *)info allKeys]) {
            printf("      %s: %s\n", SafeString(key).UTF8String, DescribeString(((NSDictionary *)info)[key]).UTF8String);
        }
    } else {
        printf("    info: %s\n", info ? class_getName([info class]) : "nil");
    }
    if ([acl isKindOfClass:[NSDictionary class]]) {
        printf("    acl keys: %lu\n", (unsigned long)[(NSDictionary *)acl count]);
    } else {
        printf("    acl: %s\n", acl ? class_getName([acl class]) : "nil");
    }
}

static void TryRPIdentityFromPeer(NSString *jsonPath, NSUInteger maxType) {
    LoadContinuityFrameworks();

    NSDictionary *json = LoadJSONDictionary(jsonPath);
    if (!json) {
        return;
    }
    id peer = BuildPairedPeerFromJSON(json);
    if (!peer) {
        return;
    }

    Class identityClass = NSClassFromString(@"RPIdentity");
    if (!identityClass) {
        fprintf(stderr, "RPIdentity not found\n");
        return;
    }

    SEL initSelector = @selector(initWithPairedPeer:type:);
    for (NSUInteger type = 0; type <= maxType; type++) {
        id identity = [[identityClass alloc] init];
        if (![identity respondsToSelector:initSelector]) {
            puts("initWithPairedPeer:type: unavailable");
            return;
        }
        typedef id (*InitFn)(id, SEL, id, int);
        InitFn initFn = (InitFn)[identity methodForSelector:initSelector];
        identity = initFn(identity, initSelector, peer, (int)type);
        printf("rpidentity type candidate %lu:\n", (unsigned long)type);
        PrintRPIdentityShape(identity);
    }
}

static id BuildRPIdentityFromPeerJSON(NSString *jsonPath, int type) {
    NSDictionary *json = LoadJSONDictionary(jsonPath);
    if (!json) {
        return nil;
    }
    NSString *identifier = [json[@"identifier"] isKindOfClass:[NSString class]] ? json[@"identifier"] : nil;
    id peer = BuildPairedPeerFromJSON(json);
    if (!peer) {
        return nil;
    }

    Class identityClass = NSClassFromString(@"RPIdentity");
    if (!identityClass) {
        fprintf(stderr, "RPIdentity not found\n");
        return nil;
    }
    id identity = [[identityClass alloc] init];
    SEL initSelector = @selector(initWithPairedPeer:type:);
    if (![identity respondsToSelector:initSelector]) {
        puts("initWithPairedPeer:type: unavailable");
        return nil;
    }
    typedef id (*InitFn)(id, SEL, id, int);
    InitFn initFn = (InitFn)[identity methodForSelector:initSelector];
    identity = initFn(identity, initSelector, peer, type);
    if (identifier.length > 0) {
        if ([identity respondsToSelector:@selector(setIdentifier:)]) {
            [identity setValue:identifier forKey:@"identifier"];
        }
        if ([identity respondsToSelector:@selector(setIdsDeviceID:)]) {
            [identity setValue:identifier forKey:@"idsDeviceID"];
        }
        if ([identity respondsToSelector:@selector(setMediaRemoteID:)]) {
            [identity setValue:identifier forKey:@"mediaRemoteID"];
        }
    }
    if ([identity respondsToSelector:@selector(setDateAdded:)]) {
        [identity setValue:[NSDate date] forKey:@"dateAdded"];
    }
    if ([identity respondsToSelector:@selector(setDateAcknowledged:)]) {
        [identity setValue:[NSDate date] forKey:@"dateAcknowledged"];
    }
    if ([identity respondsToSelector:@selector(setPresent:)]) {
        [identity setValue:@YES forKey:@"present"];
    }
    if ([identity respondsToSelector:@selector(setUserAdded:)]) {
        [identity setValue:@YES forKey:@"userAdded"];
    }
    return identity;
}

static id NewRPClient(void) {
    Class clientClass = NSClassFromString(@"RPClient");
    if (!clientClass) {
        return nil;
    }
    id client = [[clientClass alloc] init];
    if ([client respondsToSelector:@selector(setDispatchQueue:)]) {
        typedef void (*SetQueueFn)(id, SEL, dispatch_queue_t);
        SetQueueFn setQueue = (SetQueueFn)[client methodForSelector:@selector(setDispatchQueue:)];
        setQueue(client, @selector(setDispatchQueue:), dispatch_get_main_queue());
    }
    if ([client respondsToSelector:@selector(setTargetUserSession:)]) {
        typedef void (*SetBoolFn)(id, SEL, BOOL);
        SetBoolFn setTargetUserSession = (SetBoolFn)[client methodForSelector:@selector(setTargetUserSession:)];
        setTargetUserSession(client, @selector(setTargetUserSession:), YES);
    }
    return client;
}

static void TryRPClientListIdentities(uint32_t flags) {
    LoadContinuityFrameworks();

    id client = NewRPClient();
    if (!client) {
        fprintf(stderr, "RPClient not found\n");
        return;
    }

    SEL selector = @selector(getIdentitiesWithFlags:completion:);
    if (![client respondsToSelector:selector]) {
        puts("getIdentitiesWithFlags:completion: unavailable");
        return;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    typedef void (*GetIdentitiesFn)(id, SEL, uint32_t, void (^)(NSArray *, NSError *));
    GetIdentitiesFn getIdentities = (GetIdentitiesFn)[client methodForSelector:selector];
    getIdentities(client, selector, flags, ^(NSArray *identities, NSError *error) {
        if (error) {
            printf("getIdentities error: %s\n", error.description.UTF8String);
        }
        printf("identities: %lu\n", (unsigned long)identities.count);
        NSUInteger index = 0;
        for (id identity in identities) {
            printf("identity %lu:\n", (unsigned long)index++);
            PrintRPIdentityShape(identity);
        }
        dispatch_semaphore_signal(sem);
    });
    if (!WaitForSemaphore(sem, 5.0)) {
        puts("getIdentities timeout");
    }
}

static void TryRPClientAddIdentity(NSString *jsonPath, int type, int source, BOOL withSource) {
    LoadContinuityFrameworks();

    id identity = BuildRPIdentityFromPeerJSON(jsonPath, type);
    if (!identity) {
        return;
    }
    puts("constructed RPIdentity:");
    PrintRPIdentityShape(identity);

    id client = NewRPClient();
    if (!client) {
        fprintf(stderr, "RPClient not found\n");
        return;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    if (withSource) {
        SEL selector = @selector(addOrUpdateIdentity:source:completion:);
        if (![client respondsToSelector:selector]) {
            puts("addOrUpdateIdentity:source:completion: unavailable");
            return;
        }

        typedef void (*AddIdentityFn)(id, SEL, id, int, void (^)(NSError *));
        AddIdentityFn addIdentity = (AddIdentityFn)[client methodForSelector:selector];
        addIdentity(client, selector, identity, source, ^(NSError *error) {
            if (error) {
                printf("addOrUpdateIdentity:source error: %s\n", error.description.UTF8String);
            } else {
                puts("addOrUpdateIdentity:source completed without error");
            }
            dispatch_semaphore_signal(sem);
        });
    } else {
        SEL selector = @selector(addOrUpdateIdentity:completion:);
        if (![client respondsToSelector:selector]) {
            puts("addOrUpdateIdentity:completion: unavailable");
            return;
        }

        typedef void (*AddIdentityNoSourceFn)(id, SEL, id, void (^)(NSError *));
        AddIdentityNoSourceFn addIdentity = (AddIdentityNoSourceFn)[client methodForSelector:selector];
        addIdentity(client, selector, identity, ^(NSError *error) {
            if (error) {
                printf("addOrUpdateIdentity error: %s\n", error.description.UTF8String);
            } else {
                puts("addOrUpdateIdentity completed without error");
            }
            dispatch_semaphore_signal(sem);
        });
    }

    if (!WaitForSemaphore(sem, 5.0)) {
        puts("addOrUpdateIdentity timeout");
    }
}

static void TryRPClientDiagnosticCommand(NSString *command, id params) {
    LoadContinuityFrameworks();

    id client = NewRPClient();
    if (!client) {
        fprintf(stderr, "RPClient not found\n");
        return;
    }

    SEL selector = @selector(diagnosticCommand:params:completion:);
    if (![client respondsToSelector:selector]) {
        puts("diagnosticCommand:params:completion: unavailable");
        return;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    typedef void (*DiagnosticFn)(id, SEL, id, id, void (^)(id, NSError *));
    DiagnosticFn diagnostic = (DiagnosticFn)[client methodForSelector:selector];
    diagnostic(client, selector, command, params ?: @{}, ^(id result, NSError *error) {
        if (error) {
            printf("diagnosticCommand error: %s\n", error.description.UTF8String);
        } else {
            printf("diagnosticCommand result class=%s description=%s\n",
                   result ? class_getName([result class]) : "nil",
                   SafeString(result).UTF8String);
        }
        dispatch_semaphore_signal(sem);
    });
    if (!WaitForSemaphore(sem, 5.0)) {
        puts("diagnosticCommand timeout");
    }
}

static void TryRPClientEndpointMapping(NSString *applicationService, NSString *deviceID, NSString *endpointID) {
    LoadContinuityFrameworks();

    id client = NewRPClient();
    if (!client) {
        fprintf(stderr, "RPClient not found\n");
        return;
    }

    SEL selector = @selector(createEndpointToDeviceMapping:deviceID:endpointID:completion:);
    if (![client respondsToSelector:selector]) {
        puts("createEndpointToDeviceMapping:deviceID:endpointID:completion: unavailable");
        return;
    }

    printf("createEndpointToDeviceMapping applicationService=%s deviceID=%s endpointID=%s\n",
           applicationService.UTF8String,
           deviceID.UTF8String,
           endpointID.UTF8String);

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    typedef void (*MappingFn)(id, SEL, id, id, id, void (^)(NSError *));
    MappingFn createMapping = (MappingFn)[client methodForSelector:selector];
    createMapping(client, selector, applicationService, deviceID, endpointID, ^(NSError *error) {
        if (error) {
            printf("createEndpointToDeviceMapping error: %s\n", error.description.UTF8String);
        } else {
            puts("createEndpointToDeviceMapping completed without error");
        }
        dispatch_semaphore_signal(sem);
    });
    if (!WaitForSemaphore(sem, 5.0)) {
        puts("createEndpointToDeviceMapping timeout");
    }
}

static void TryRPClientInternalDeviceMapping(int mappingType, NSString *applicationService, NSString *deviceID, NSString *endpointID) {
    LoadContinuityFrameworks();

    id client = NewRPClient();
    if (!client) {
        fprintf(stderr, "RPClient not found\n");
        return;
    }

    SEL selector = @selector(clientCreateDeviceMappingInternal:applicationService:deviceID:endpointID:completion:);
    if (![client respondsToSelector:selector]) {
        puts("clientCreateDeviceMappingInternal:applicationService:deviceID:endpointID:completion: unavailable");
        return;
    }

    printf("clientCreateDeviceMappingInternal type=%d applicationService=%s deviceID=%s endpointID=%s\n",
           mappingType,
           applicationService.UTF8String,
           deviceID.UTF8String,
           endpointID.UTF8String);

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    typedef void (*MappingFn)(id, SEL, int, id, id, id, void (^)(NSError *));
    MappingFn createMapping = (MappingFn)[client methodForSelector:selector];
    createMapping(client, selector, mappingType, applicationService, deviceID, endpointID, ^(NSError *error) {
        if (error) {
            printf("clientCreateDeviceMappingInternal error: %s\n", error.description.UTF8String);
        } else {
            puts("clientCreateDeviceMappingInternal completed without error");
        }
        dispatch_semaphore_signal(sem);
    });
    if (!WaitForSemaphore(sem, 5.0)) {
        puts("clientCreateDeviceMappingInternal timeout");
    }
}

static void TryRPClientDeviceToListenerMapping(NSString *listenerID, NSString *deviceID) {
    LoadContinuityFrameworks();

    id client = NewRPClient();
    if (!client) {
        fprintf(stderr, "RPClient not found\n");
        return;
    }

    SEL selector = @selector(createDeviceToListenerMapping:deviceID:completion:);
    if (![client respondsToSelector:selector]) {
        puts("createDeviceToListenerMapping:deviceID:completion: unavailable");
        return;
    }

    printf("createDeviceToListenerMapping listenerID=%s deviceID=%s\n",
           listenerID.UTF8String,
           deviceID.UTF8String);

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    typedef void (*MappingFn)(id, SEL, id, id, void (^)(NSError *));
    MappingFn createMapping = (MappingFn)[client methodForSelector:selector];
    createMapping(client, selector, listenerID, deviceID, ^(NSError *error) {
        if (error) {
            printf("createDeviceToListenerMapping error: %s\n", error.description.UTF8String);
        } else {
            puts("createDeviceToListenerMapping completed without error");
        }
        dispatch_semaphore_signal(sem);
    });
    if (!WaitForSemaphore(sem, 5.0)) {
        puts("createDeviceToListenerMapping timeout");
    }
}

static void TryRPClientQueryDeviceToListenerMapping(NSString *listenerID, NSString *deviceID) {
    LoadContinuityFrameworks();

    id client = NewRPClient();
    if (!client) {
        fprintf(stderr, "RPClient not found\n");
        return;
    }

    SEL selector = @selector(queryDeviceToListenerMapping:deviceID:completion:);
    if (![client respondsToSelector:selector]) {
        puts("queryDeviceToListenerMapping:deviceID:completion: unavailable");
        return;
    }

    printf("queryDeviceToListenerMapping listenerID=%s deviceID=%s\n",
           listenerID.UTF8String,
           deviceID.UTF8String);

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    typedef void (*QueryFn)(id, SEL, id, id, void (^)(id, NSError *));
    QueryFn queryMapping = (QueryFn)[client methodForSelector:selector];
    queryMapping(client, selector, listenerID, deviceID, ^(id result, NSError *error) {
        if (error) {
            printf("queryDeviceToListenerMapping error: %s\n", error.description.UTF8String);
        } else {
            printf("queryDeviceToListenerMapping result: class=%s value=%s\n",
                   result ? class_getName([result class]) : "nil",
                   RedactedLength(result).UTF8String);
        }
        dispatch_semaphore_signal(sem);
    });
    if (!WaitForSemaphore(sem, 5.0)) {
        puts("queryDeviceToListenerMapping timeout");
    }
}

static void TryRPClientSetAutoMapping(BOOL enabled) {
    LoadContinuityFrameworks();

    id client = NewRPClient();
    if (!client) {
        fprintf(stderr, "RPClient not found\n");
        return;
    }

    SEL selector = @selector(setAutoMapping:completion:);
    if (![client respondsToSelector:selector]) {
        puts("setAutoMapping:completion: unavailable");
        return;
    }

    printf("setAutoMapping enabled=%s\n", enabled ? "yes" : "no");
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    typedef void (*AutoMappingFn)(id, SEL, BOOL, void (^)(NSError *));
    AutoMappingFn setAutoMapping = (AutoMappingFn)[client methodForSelector:selector];
    setAutoMapping(client, selector, enabled, ^(NSError *error) {
        if (error) {
            printf("setAutoMapping error: %s\n", error.description.UTF8String);
        } else {
            puts("setAutoMapping completed without error");
        }
        dispatch_semaphore_signal(sem);
    });
    if (!WaitForSemaphore(sem, 5.0)) {
        puts("setAutoMapping timeout");
    }
}

static void PrintCompanionLinkDeviceSummary(const char *label, id device, uint32_t changes) {
    if (!device) {
        printf("%s device=nil changes=0x%x\n", label, changes);
        return;
    }

    id identifier = SafeValueForKey(device, @"identifier");
    id idsIdentifier = SafeValueForKey(device, @"idsDeviceIdentifier");
    id idsPersonalIdentifier = SafeValueForKey(device, @"idsPersonalDeviceIdentifier");
    id name = SafeValueForKey(device, @"name");
    id model = SafeValueForKey(device, @"model");
    id modelIdentifier = SafeValueForKey(device, @"modelIdentifier");
    id effectiveIdentifier = SafeValueForKey(device, @"effectiveIdentifier");
    id publicIdentifier = SafeValueForKey(device, @"publicIdentifier");
    id pairingIdentifier = SafeValueForKey(device, @"pairingIdentifier");

    printf("%s class=%s changes=0x%x\n", label, class_getName([device class]), changes);
    printf("  description: %s\n", SafeString(device).UTF8String);
    printf("  identifier: %s\n", DescribeString(identifier).UTF8String);
    printf("  effectiveIdentifier: %s\n", DescribeString(effectiveIdentifier).UTF8String);
    printf("  publicIdentifier: %s\n", DescribeString(publicIdentifier).UTF8String);
    printf("  pairingIdentifier: %s\n", DescribeString(pairingIdentifier).UTF8String);
    printf("  idsDeviceIdentifier: %s\n", DescribeString(idsIdentifier).UTF8String);
    printf("  idsPersonalDeviceIdentifier: %s\n", DescribeString(idsPersonalIdentifier).UTF8String);
    printf("  name: %s\n", DescribeString(name).UTF8String);
    printf("  model: %s\n", DescribeString(model).UTF8String);
    printf("  modelIdentifier: %s\n", DescribeString(modelIdentifier).UTF8String);

    BOOL personal = NO;
    if (ReadBoolSelector(device, @selector(isPersonal), &personal)) {
        printf("  personal: %s\n", personal ? "yes" : "no");
    }

    if ([device respondsToSelector:@selector(flags)]) {
        typedef uint32_t (*UIntGetterFn)(id, SEL);
        UIntGetterFn flagsFn = (UIntGetterFn)[device methodForSelector:@selector(flags)];
        printf("  flags: 0x%x\n", flagsFn(device, @selector(flags)));
    }
    if ([device respondsToSelector:@selector(deviceCapabilityFlags)]) {
        typedef uint32_t (*UIntGetterFn)(id, SEL);
        UIntGetterFn flagsFn = (UIntGetterFn)[device methodForSelector:@selector(deviceCapabilityFlags)];
        printf("  deviceCapabilityFlags: 0x%x\n", flagsFn(device, @selector(deviceCapabilityFlags)));
    }
    if ([device respondsToSelector:@selector(statusFlags)]) {
        typedef uint64_t (*UInt64GetterFn)(id, SEL);
        UInt64GetterFn flagsFn = (UInt64GetterFn)[device methodForSelector:@selector(statusFlags)];
        printf("  statusFlags: 0x%llx\n", (unsigned long long)flagsFn(device, @selector(statusFlags)));
    }
}

static id CopyObjectProperty(id object, SEL selector) {
    if (!object || ![object respondsToSelector:selector]) {
        return nil;
    }
    typedef id (*GetterFn)(id, SEL);
    GetterFn fn = (GetterFn)[object methodForSelector:selector];
    return fn ? fn(object, selector) : nil;
}

static void PrintPairingControllerXPCState(id controller, const char *label) {
    id connection = nil;
    @try {
        connection = [controller valueForKey:@"xpcCnx"];
    } @catch (__unused NSException *exception) {
        connection = nil;
    }

    printf("%s.xpcCnx.class=%s description=%s\n",
           label,
           connection ? class_getName([connection class]) : "nil",
           connection ? SafeString(connection).UTF8String : "nil");
    if (!connection) {
        return;
    }

    id serviceName = CopyObjectProperty(connection, @selector(serviceName));
    printf("%s.xpcCnx.serviceName=%s\n",
           label,
           serviceName ? SafeString(serviceName).UTF8String : "nil");

    id remoteInterface = CopyObjectProperty(connection, @selector(remoteObjectInterface));
    printf("%s.xpcCnx.remoteObjectInterface=%s\n",
           label,
           remoteInterface ? SafeString(remoteInterface).UTF8String : "nil");

    id exportedInterface = CopyObjectProperty(connection, @selector(exportedInterface));
    printf("%s.xpcCnx.exportedInterface=%s\n",
           label,
           exportedInterface ? SafeString(exportedInterface).UTF8String : "nil");

    id exportedObject = CopyObjectProperty(connection, @selector(exportedObject));
    printf("%s.xpcCnx.exportedObject=%s\n",
           label,
           exportedObject ? SafeString(exportedObject).UTF8String : "nil");

    id endpoint = CopyObjectProperty(connection, @selector(endpoint));
    printf("%s.xpcCnx.endpoint=%s\n",
           label,
           endpoint ? SafeString(endpoint).UTF8String : "nil");
}

static void TryRPCompanionLinkBrowse(NSString *serviceType,
                                     NSTimeInterval seconds,
                                     uint32_t flags,
                                     uint64_t controlFlags,
                                     uint32_t useCase) {
    LoadContinuityFrameworks();

    Class clientClass = NSClassFromString(@"RPCompanionLinkClient");
    if (!clientClass) {
        fprintf(stderr, "RPCompanionLinkClient not found\n");
        return;
    }

    id client = [[clientClass alloc] init];
    if (!client) {
        fprintf(stderr, "failed to allocate RPCompanionLinkClient\n");
        return;
    }

    if ([client respondsToSelector:@selector(setDispatchQueue:)]) {
        typedef void (*SetQueueFn)(id, SEL, dispatch_queue_t);
        SetQueueFn fn = (SetQueueFn)[client methodForSelector:@selector(setDispatchQueue:)];
        fn(client, @selector(setDispatchQueue:), dispatch_get_main_queue());
    }
    if ([client respondsToSelector:@selector(setTargetUserSession:)]) {
        typedef void (*SetBoolFn)(id, SEL, BOOL);
        SetBoolFn fn = (SetBoolFn)[client methodForSelector:@selector(setTargetUserSession:)];
        fn(client, @selector(setTargetUserSession:), YES);
    }
    if ([client respondsToSelector:@selector(setAppID:)]) {
        typedef void (*SetObjectFn)(id, SEL, id);
        SetObjectFn fn = (SetObjectFn)[client methodForSelector:@selector(setAppID:)];
        fn(client, @selector(setAppID:), serviceType);
    }
    if ([client respondsToSelector:@selector(setServiceType:)]) {
        typedef void (*SetObjectFn)(id, SEL, id);
        SetObjectFn fn = (SetObjectFn)[client methodForSelector:@selector(setServiceType:)];
        fn(client, @selector(setServiceType:), serviceType);
    }
    if ([client respondsToSelector:@selector(setFlags:)]) {
        typedef void (*SetUIntFn)(id, SEL, uint32_t);
        SetUIntFn fn = (SetUIntFn)[client methodForSelector:@selector(setFlags:)];
        fn(client, @selector(setFlags:), flags);
    }
    if ([client respondsToSelector:@selector(setControlFlags:)]) {
        typedef void (*SetUInt64Fn)(id, SEL, uint64_t);
        SetUInt64Fn fn = (SetUInt64Fn)[client methodForSelector:@selector(setControlFlags:)];
        fn(client, @selector(setControlFlags:), controlFlags);
    }
    if ([client respondsToSelector:@selector(setUseCase:)]) {
        typedef void (*SetUIntFn)(id, SEL, uint32_t);
        SetUIntFn fn = (SetUIntFn)[client methodForSelector:@selector(setUseCase:)];
        fn(client, @selector(setUseCase:), useCase);
    }

    __block NSUInteger eventCount = 0;
    if ([client respondsToSelector:@selector(setDeviceFoundHandler:)]) {
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[client methodForSelector:@selector(setDeviceFoundHandler:)];
        fn(client, @selector(setDeviceFoundHandler:), ^(id device) {
            eventCount++;
            PrintCompanionLinkDeviceSummary("device found", device, 0);
        });
    }
    if ([client respondsToSelector:@selector(setDeviceLostHandler:)]) {
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[client methodForSelector:@selector(setDeviceLostHandler:)];
        fn(client, @selector(setDeviceLostHandler:), ^(id device) {
            eventCount++;
            PrintCompanionLinkDeviceSummary("device lost", device, 0);
        });
    }
    if ([client respondsToSelector:@selector(setDeviceChangedHandler:)]) {
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[client methodForSelector:@selector(setDeviceChangedHandler:)];
        fn(client, @selector(setDeviceChangedHandler:), ^(id device, uint32_t changes) {
            eventCount++;
            PrintCompanionLinkDeviceSummary("device changed", device, changes);
        });
    }
    if ([client respondsToSelector:@selector(setLocalDeviceUpdatedHandler:)]) {
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[client methodForSelector:@selector(setLocalDeviceUpdatedHandler:)];
        fn(client, @selector(setLocalDeviceUpdatedHandler:), ^(id device) {
            PrintCompanionLinkDeviceSummary("local device updated", device, 0);
        });
    }
    if ([client respondsToSelector:@selector(setInterruptionHandler:)]) {
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[client methodForSelector:@selector(setInterruptionHandler:)];
        fn(client, @selector(setInterruptionHandler:), ^{
            puts("RPCompanionLinkClient interrupted");
        });
    }
    if ([client respondsToSelector:@selector(setInvalidationHandler:)]) {
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[client methodForSelector:@selector(setInvalidationHandler:)];
        fn(client, @selector(setInvalidationHandler:), ^{
            puts("RPCompanionLinkClient invalidated");
        });
    }
    if ([client respondsToSelector:@selector(setDisconnectHandler:)]) {
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[client methodForSelector:@selector(setDisconnectHandler:)];
        fn(client, @selector(setDisconnectHandler:), ^{
            puts("RPCompanionLinkClient disconnected");
        });
    }

    printf("activating RPCompanionLinkClient serviceType=%s seconds=%.1f flags=0x%x controlFlags=0x%llx useCase=0x%x\n",
           serviceType.UTF8String,
           seconds,
           flags,
           (unsigned long long)controlFlags,
           useCase);

    dispatch_semaphore_t activationSem = dispatch_semaphore_create(0);
    if ([client respondsToSelector:@selector(activateWithCompletion:)]) {
        typedef void (*ActivateFn)(id, SEL, void (^)(NSError *));
        ActivateFn activate = (ActivateFn)[client methodForSelector:@selector(activateWithCompletion:)];
        activate(client, @selector(activateWithCompletion:), ^(NSError *error) {
            if (error) {
                printf("RPCompanionLinkClient activation error: %s\n", error.description.UTF8String);
            } else {
                puts("RPCompanionLinkClient activated");
            }
            dispatch_semaphore_signal(activationSem);
        });
    } else {
        puts("activateWithCompletion: unavailable");
        return;
    }

    WaitForSemaphore(activationSem, 5.0);
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
    while ([deadline timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }

    if ([client respondsToSelector:@selector(activeDevices)]) {
        NSArray *devices = [client valueForKey:@"activeDevices"];
        printf("activeDevices: %lu\n", (unsigned long)devices.count);
        NSUInteger index = 0;
        for (id device in devices) {
            char label[64];
            snprintf(label, sizeof(label), "active device %lu", (unsigned long)index++);
            PrintCompanionLinkDeviceSummary(label, device, 0);
        }
    }
    printf("events: %lu\n", (unsigned long)eventCount);

    if ([client respondsToSelector:@selector(invalidate)]) {
        typedef void (*VoidFn)(id, SEL);
        VoidFn invalidate = (VoidFn)[client methodForSelector:@selector(invalidate)];
        invalidate(client, @selector(invalidate));
    }
}

static void DumpNetworkApplicationServiceDescriptors(NSString *serviceName) {
    LoadContinuityFrameworks();

    nw_browse_descriptor_t browseDescriptor =
        nw_browse_descriptor_create_application_service(serviceName.UTF8String);
    nw_advertise_descriptor_t advertiseDescriptor =
        nw_advertise_descriptor_create_application_service(serviceName.UTF8String);

    printf("application service=%s\n", serviceName.UTF8String);
    printf("nw_browse_descriptor=%s\n", browseDescriptor ? [[(id)browseDescriptor description] UTF8String] : "nil");
    printf("nw_advertise_descriptor=%s\n", advertiseDescriptor ? [[(id)advertiseDescriptor description] UTF8String] : "nil");

    Class browseWrapperClass = NSClassFromString(@"NWBrowseDescriptor");
    SEL wrapBrowseSelector = @selector(descriptorWithInternalDescriptor:);
    id browseWrapper = nil;
    if (browseDescriptor && [browseWrapperClass respondsToSelector:wrapBrowseSelector]) {
        typedef id (*WrapBrowseFn)(id, SEL, id);
        WrapBrowseFn wrap = (WrapBrowseFn)[browseWrapperClass methodForSelector:wrapBrowseSelector];
        browseWrapper = wrap(browseWrapperClass, wrapBrowseSelector, (id)browseDescriptor);
    }

    if (browseWrapper) {
        printf("NWBrowseDescriptor class=%s description=%s\n",
               class_getName([browseWrapper class]),
               [[browseWrapper description] UTF8String]);
        if ([browseWrapper respondsToSelector:@selector(encodedData)]) {
            typedef id (*EncodedFn)(id, SEL);
            EncodedFn encoded = (EncodedFn)[browseWrapper methodForSelector:@selector(encodedData)];
            NSData *data = encoded(browseWrapper, @selector(encodedData));
            printf("NWBrowseDescriptor encodedData=%s hex=%s\n",
                   DescribeData(data).UTF8String,
                   HexString(data, 256).UTF8String);

            SEL protocolBufferSelector = @selector(descriptorWithProtocolBufferData:);
            if (data && [browseWrapperClass respondsToSelector:protocolBufferSelector]) {
                typedef id (*PBWrapFn)(id, SEL, id);
                PBWrapFn fromPB = (PBWrapFn)[browseWrapperClass methodForSelector:protocolBufferSelector];
                id decoded = fromPB(browseWrapperClass, protocolBufferSelector, data);
                printf("NWBrowseDescriptor decodedFromPB class=%s description=%s\n",
                       decoded ? class_getName([decoded class]) : "nil",
                       decoded ? [[decoded description] UTF8String] : "nil");
            }

            Class pbClass = NSClassFromString(@"NWPBBrowseDescriptor");
            if (data && pbClass) {
                id pb = [[pbClass alloc] init];
                if ([pb respondsToSelector:@selector(readFrom:)]) {
                    typedef BOOL (*ReadFn)(id, SEL, id);
                    ReadFn read = (ReadFn)[pb methodForSelector:@selector(readFrom:)];
                    BOOL ok = read(pb, @selector(readFrom:), data);
                    printf("NWPBBrowseDescriptor read=%s description=%s\n",
                           ok ? "yes" : "no",
                           [[pb description] UTF8String]);
                    Ivar serviceIvar = class_getInstanceVariable(pbClass, "_service");
                    id service = serviceIvar ? object_getIvar(pb, serviceIvar) : nil;
                    printf("NWPBBrowseDescriptor service=%s\n",
                           service ? [[service description] UTF8String] : "nil");
                }
            }
        }
    } else {
        puts("NWBrowseDescriptor wrapper unavailable");
    }

    Class advertiseWrapperClass = NSClassFromString(@"NWAdvertiseDescriptor");
    id advertiseWrapper = nil;
    if (advertiseDescriptor && advertiseWrapperClass) {
        SEL initSelector = @selector(initWithDescriptor:);
        if ([advertiseWrapperClass instancesRespondToSelector:initSelector]) {
            typedef id (*InitAdvertiseFn)(id, SEL, id);
            id allocated = [advertiseWrapperClass alloc];
            InitAdvertiseFn init = (InitAdvertiseFn)[allocated methodForSelector:initSelector];
            advertiseWrapper = init(allocated, initSelector, (id)advertiseDescriptor);
        }
    }

    if (advertiseWrapper) {
        printf("NWAdvertiseDescriptor class=%s description=%s\n",
               class_getName([advertiseWrapper class]),
               [[advertiseWrapper description] UTF8String]);
    } else {
        puts("NWAdvertiseDescriptor wrapper unavailable");
    }
}

static nw_browse_descriptor_t CreateApplicationServiceBrowseDescriptor(NSString *serviceName, NSString *bundleID) {
    if (bundleID.length > 0) {
        typedef nw_browse_descriptor_t (*CreateWithBundleFn)(const char *, const char *);
        CreateWithBundleFn createWithBundle = (CreateWithBundleFn)dlsym(RTLD_DEFAULT, "nw_browse_descriptor_create_application_service_with_bundle_id");
        if (createWithBundle) {
            return createWithBundle(serviceName.UTF8String, bundleID.UTF8String);
        }
        puts("nw_browse_descriptor_create_application_service_with_bundle_id unavailable; using public constructor");
    }
    return nw_browse_descriptor_create_application_service(serviceName.UTF8String);
}

static nw_advertise_descriptor_t CreateApplicationServiceAdvertiseDescriptor(NSString *serviceName, NSString *bundleID) {
    if (bundleID.length > 0) {
        typedef nw_advertise_descriptor_t (*CreateWithBundleFn)(const char *, const char *);
        CreateWithBundleFn createWithBundle = (CreateWithBundleFn)dlsym(RTLD_DEFAULT, "nw_advertise_descriptor_create_application_service_with_bundle_id");
        if (createWithBundle) {
            return createWithBundle(serviceName.UTF8String, bundleID.UTF8String);
        }
        puts("nw_advertise_descriptor_create_application_service_with_bundle_id unavailable; using public constructor");
    }
    return nw_advertise_descriptor_create_application_service(serviceName.UTF8String);
}

static NSData *DataFromProbeArgument(NSString *argument) {
    if (argument.length == 0) {
        return nil;
    }
    if ([argument hasPrefix:@"@"]) {
        NSString *path = [argument substringFromIndex:1];
        NSData *data = [NSData dataWithContentsOfFile:path];
        if (!data) {
            fprintf(stderr, "failed to read data file: %s\n", path.UTF8String);
        }
        return data;
    }
    if ([argument hasPrefix:@"hex:"]) {
        NSError *error = nil;
        NSData *data = DataFromHexString([argument substringFromIndex:4], &error);
        if (!data) {
            fprintf(stderr, "invalid hex data: %s\n", error.description.UTF8String);
        }
        return data;
    }
    if ([argument hasPrefix:@"json:"]) {
        return [[argument substringFromIndex:5] dataUsingEncoding:NSUTF8StringEncoding];
    }
    return [argument dataUsingEncoding:NSUTF8StringEncoding];
}

static NSData *JSONDataFromObject(id object) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:&error];
    if (!data) {
        fprintf(stderr, "failed to encode JSON data: %s\n", error.description.UTF8String);
    }
    return data;
}

static NSData *ListenerPinPairingCustomService(NSString *pin) {
    return JSONDataFromObject(@{
        @"pairingValue": @{@"pin": @{@"_0": pin.length > 0 ? pin : @"123456"}},
        @"supportedPairingTypes": @[@{@"pin": @{}}],
        @"generatePairingValueImmediately": @YES,
        @"_advertiseSensitiveInfo": @YES,
    });
}

static NSData *BrowserPinPairingCustomService(void) {
    return JSONDataFromObject(@{
        @"pairingType": @{@"pin": @{}},
        @"preferredPairingTypes": @[@{@"pin": @{}}],
    });
}

static BOOL SetBrowseDescriptorCustomService(nw_browse_descriptor_t descriptor, NSData *customService) {
    if (!customService) {
        return YES;
    }

    typedef void (*SetCustomServiceFn)(nw_browse_descriptor_t, const void *, size_t);
    SetCustomServiceFn setCustomService =
        (SetCustomServiceFn)dlsym(RTLD_DEFAULT, "nw_browse_descriptor_set_custom_service");
    if (!setCustomService) {
        puts("nw_browse_descriptor_set_custom_service unavailable");
        return NO;
    }

    setCustomService(descriptor, customService.bytes, customService.length);
    printf("browse customService set: %s hex=%s\n",
           DescribeData(customService).UTF8String,
           HexString(customService, 128).UTF8String);
    return YES;
}

static BOOL SetAdvertiseDescriptorCustomService(nw_advertise_descriptor_t descriptor, NSData *customService) {
    if (!customService) {
        return YES;
    }

    typedef void (*SetCustomServiceFn)(nw_advertise_descriptor_t, const void *, size_t);
    SetCustomServiceFn setCustomService =
        (SetCustomServiceFn)dlsym(RTLD_DEFAULT, "nw_advertise_descriptor_set_custom_service");
    if (!setCustomService) {
        puts("nw_advertise_descriptor_set_custom_service unavailable");
        return NO;
    }

    setCustomService(descriptor, customService.bytes, customService.length);
    printf("advertise customService set: %s hex=%s\n",
           DescribeData(customService).UTF8String,
           HexString(customService, 128).UTF8String);
    return YES;
}

static void RunNetworkApplicationServiceBrowse(NSString *serviceName, NSString *bundleID, NSTimeInterval seconds, NSData *customService) {
    LoadContinuityFrameworks();

    nw_browse_descriptor_t descriptor = CreateApplicationServiceBrowseDescriptor(serviceName, bundleID);
    if (!SetBrowseDescriptorCustomService(descriptor, customService)) {
        return;
    }
    nw_parameters_t parameters = nw_parameters_create_application_service();
    nw_browser_t browser = nw_browser_create(descriptor, parameters);
    if (!browser) {
        puts("nw_browser_create failed");
        return;
    }

    printf("nw-appsvc-browse service=%s bundle=%s seconds=%.1f descriptor=%s\n",
           serviceName.UTF8String,
           bundleID.length > 0 ? bundleID.UTF8String : "(default)",
           seconds,
           [[(id)descriptor description] UTF8String]);

    dispatch_queue_t queue = dispatch_queue_create("macolinux.nw-appsvc-browse", DISPATCH_QUEUE_SERIAL);
    nw_browser_set_queue(browser, queue);
    nw_browser_set_state_changed_handler(browser, ^(nw_browser_state_t state, nw_error_t error) {
        printf("browser state=%s", NetworkBrowserStateName(state));
        if (error) {
            printf(" error=%s", [[(id)error description] UTF8String]);
        }
        puts("");
    });
    nw_browser_set_browse_results_changed_handler(browser, ^(nw_browse_result_t oldResult, nw_browse_result_t newResult, bool batchComplete) {
        nw_browse_result_change_t changes = nw_browse_result_get_changes(oldResult, newResult);
        nw_browse_result_t result = newResult ?: oldResult;
        nw_endpoint_t endpoint = result ? nw_browse_result_copy_endpoint(result) : nil;
        printf("browser result changes=0x%llx batchComplete=%s endpoint=%s\n",
               (unsigned long long)changes,
               batchComplete ? "yes" : "no",
               endpoint ? [[(id)endpoint description] UTF8String] : "nil");
    });
    nw_browser_start(browser);

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
    while ([deadline timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }

    nw_browser_cancel(browser);
    [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.3]];
}

static void RunNetworkApplicationServiceListen(NSString *serviceName, NSString *bundleID, NSTimeInterval seconds, NSData *customService) {
    LoadContinuityFrameworks();

    nw_advertise_descriptor_t descriptor = CreateApplicationServiceAdvertiseDescriptor(serviceName, bundleID);
    if (!SetAdvertiseDescriptorCustomService(descriptor, customService)) {
        return;
    }
    nw_parameters_t parameters = nw_parameters_create_application_service();
    nw_listener_t listener = nw_listener_create(parameters);
    if (!listener) {
        puts("nw_listener_create failed");
        return;
    }
    nw_listener_set_advertise_descriptor(listener, descriptor);

    printf("nw-appsvc-listen service=%s bundle=%s seconds=%.1f descriptor=%s\n",
           serviceName.UTF8String,
           bundleID.length > 0 ? bundleID.UTF8String : "(default)",
           seconds,
           [[(id)descriptor description] UTF8String]);

    dispatch_queue_t queue = dispatch_queue_create("macolinux.nw-appsvc-listen", DISPATCH_QUEUE_SERIAL);
    nw_listener_set_queue(listener, queue);
    nw_listener_set_state_changed_handler(listener, ^(nw_listener_state_t state, nw_error_t error) {
        printf("listener state=%s", NetworkListenerStateName(state));
        if (error) {
            printf(" error=%s", [[(id)error description] UTF8String]);
        }
        puts("");
    });
    nw_listener_set_advertised_endpoint_changed_handler(listener, ^(nw_endpoint_t endpoint, bool added) {
        printf("listener advertised %s endpoint=%s\n",
               added ? "add" : "remove",
               endpoint ? [[(id)endpoint description] UTF8String] : "nil");
    });
    nw_listener_set_new_connection_handler(listener, ^(nw_connection_t connection) {
        printf("listener accepted connection=%s\n", [[(id)connection description] UTF8String]);
        nw_connection_cancel(connection);
    });
    nw_listener_start(listener);

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
    while ([deadline timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }

    nw_listener_cancel(listener);
    [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.3]];
}

static NSDictionary *LoadJSONDictionary(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) {
        fprintf(stderr, "failed to read JSON file: %s\n", path.UTF8String);
        return nil;
    }
    NSError *error = nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error) {
        fprintf(stderr, "failed to parse JSON: %s\n", error.description.UTF8String);
        return nil;
    }
    if (![object isKindOfClass:[NSDictionary class]]) {
        fprintf(stderr, "expected top-level JSON object\n");
        return nil;
    }
    return object;
}

static id BuildPairedPeerFromJSON(NSDictionary *json) {
    Class peerClass = NSClassFromString(@"CUPairedPeer");
    if (!peerClass) {
        fprintf(stderr, "CUPairedPeer not found\n");
        return nil;
    }

    NSString *identifier = [json[@"identifier"] isKindOfClass:[NSString class]] ? json[@"identifier"] : nil;
    NSString *publicKeyHex = [json[@"ed25519_public_key_hex"] isKindOfClass:[NSString class]] ? json[@"ed25519_public_key_hex"] : nil;
    if (identifier.length == 0 || publicKeyHex.length == 0) {
        fprintf(stderr, "peer JSON must contain identifier and ed25519_public_key_hex\n");
        return nil;
    }

    NSError *hexError = nil;
    NSData *publicKey = DataFromHexString(publicKeyHex, &hexError);
    if (!publicKey) {
        fprintf(stderr, "invalid public key hex: %s\n", hexError.description.UTF8String);
        return nil;
    }
    if (publicKey.length != 32) {
        fprintf(stderr, "public key must be 32 bytes, got %lu\n", (unsigned long)publicKey.length);
        return nil;
    }

    id peer = [[peerClass alloc] init];
    if ([peer respondsToSelector:@selector(setIdentifierStr:)]) {
        [peer setValue:identifier forKey:@"identifierStr"];
    }
    NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:identifier];
    if (uuid && [peer respondsToSelector:@selector(setIdentifier:)]) {
        [peer setValue:uuid forKey:@"identifier"];
    }
    if ([peer respondsToSelector:@selector(setPublicKey:)]) {
        [peer setValue:publicKey forKey:@"publicKey"];
    }
    if ([peer respondsToSelector:@selector(setLabel:)]) {
        [peer setValue:@"macolinux-dspext" forKey:@"label"];
    }
    if ([peer respondsToSelector:@selector(setModel:)]) {
        [peer setValue:@"Linux" forKey:@"model"];
    }
    if ([peer respondsToSelector:@selector(setName:)]) {
        [peer setValue:identifier forKey:@"name"];
    }
    if ([peer respondsToSelector:@selector(setInfo:)]) {
        NSDictionary *info = @{
            @"source": @"macolinux-dspext",
            @"identifier": identifier,
            @"ed25519PublicKey": publicKeyHex,
        };
        [peer setValue:info forKey:@"info"];
    }
    if ([peer respondsToSelector:@selector(setDateModified:)]) {
        [peer setValue:[NSDate date] forKey:@"dateModified"];
    }

    return peer;
}

static id NewPairingManager(void) {
    Class managerClass = NSClassFromString(@"CUPairingManager");
    if (!managerClass) {
        return nil;
    }
    id manager = [[managerClass alloc] init];
    if ([manager respondsToSelector:@selector(setDispatchQueue:)]) {
        typedef void (*SetQueueFn)(id, SEL, dispatch_queue_t);
        SetQueueFn setQueue = (SetQueueFn)[manager methodForSelector:@selector(setDispatchQueue:)];
        setQueue(manager, @selector(setDispatchQueue:), dispatch_get_main_queue());
    }
    return manager;
}

static BOOL CallSavePairedPeer(id manager, id peer, uint64_t options) {
    SEL selector = @selector(savePairedPeer:options:completion:);
    if (![manager respondsToSelector:selector]) {
        puts("savePairedPeer:options:completion: unavailable");
        return NO;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSError *completionError = nil;
    typedef void (*SaveFn)(id, SEL, id, uint64_t, void (^)(NSError *));
    SaveFn save = (SaveFn)[manager methodForSelector:selector];
    save(manager, selector, peer, options, ^(NSError *error) {
        completionError = error;
        dispatch_semaphore_signal(sem);
    });
    if (!WaitForSemaphore(sem, 5.0)) {
        puts("savePairedPeer timeout");
        return NO;
    }
    if (completionError) {
        printf("savePairedPeer error: %s\n", completionError.description.UTF8String);
        return NO;
    }
    puts("savePairedPeer completed without error");
    return YES;
}

static void TrySavePeer(NSString *jsonPath, uint64_t options) {
    LoadContinuityFrameworks();

    NSDictionary *json = LoadJSONDictionary(jsonPath);
    if (!json) {
        return;
    }
    id peer = BuildPairedPeerFromJSON(json);
    if (!peer) {
        return;
    }
    puts("constructed peer:");
    PrintPeerShape(peer, 0);

    id manager = NewPairingManager();
    if (!manager) {
        fprintf(stderr, "CUPairingManager not found\n");
        return;
    }

    printf("saving peer with options=0x%llx\n", (unsigned long long)options);
    CallSavePairedPeer(manager, peer, options);
}

static void ProbeCoreUtilsSymbols(void) {
    LoadContinuityFrameworks();
    NSArray<NSString *> *symbols = @[
        @"PairingSessionCreate",
        @"PairingSessionDeletePeer",
        @"PairingSessionFindPeer",
        @"PairingSessionSavePeer",
        @"PairingSessionSetFlags",
        @"_PairingSessionSavePeer",
        @"_PairingSessionFindPeer",
        @"_PairingSessionFindPeerEx",
        @"_KeychainAddFormatted",
        @"KeychainAddFormatted",
    ];
    for (NSString *symbol in symbols) {
        void *address = dlsym(RTLD_DEFAULT, symbol.UTF8String);
        printf("%-32s %s\n", symbol.UTF8String, address ? "available" : "missing");
    }
}

static void TryPairingSessionSavePeer(NSString *jsonPath, uint32_t sessionType, uint64_t flags) {
    LoadContinuityFrameworks();

    NSDictionary *json = LoadJSONDictionary(jsonPath);
    if (!json) {
        return;
    }
    NSString *identifier = [json[@"identifier"] isKindOfClass:[NSString class]] ? json[@"identifier"] : nil;
    NSString *publicKeyHex = [json[@"ed25519_public_key_hex"] isKindOfClass:[NSString class]] ? json[@"ed25519_public_key_hex"] : nil;
    NSError *hexError = nil;
    NSData *publicKey = DataFromHexString(publicKeyHex ?: @"", &hexError);
    if (identifier.length == 0 || publicKey.length != 32) {
        fprintf(stderr, "peer JSON must contain identifier and a 32-byte ed25519_public_key_hex\n");
        return;
    }

    typedef int32_t (*CreateFn)(void **, const void *, uint32_t);
    typedef int32_t (*SetFlagsFn)(void *, uint64_t);
    typedef int32_t (*SavePeerFn)(void *, const void *, size_t, const uint8_t *);
    typedef int32_t (*FindPeerFn)(void *, const void *, size_t, uint8_t *, CFDictionaryRef *);
    typedef void (*InvalidateFn)(void *);

    CreateFn create = (CreateFn)dlsym(RTLD_DEFAULT, "PairingSessionCreate");
    SetFlagsFn setFlags = (SetFlagsFn)dlsym(RTLD_DEFAULT, "PairingSessionSetFlags");
    SavePeerFn savePeer = (SavePeerFn)dlsym(RTLD_DEFAULT, "PairingSessionSavePeer");
    FindPeerFn findPeer = (FindPeerFn)dlsym(RTLD_DEFAULT, "PairingSessionFindPeer");
    InvalidateFn invalidate = (InvalidateFn)dlsym(RTLD_DEFAULT, "PairingSessionInvalidate");
    if (!create || !savePeer) {
        puts("PairingSessionCreate or PairingSessionSavePeer unavailable");
        return;
    }

    void *session = NULL;
    int32_t status = create(&session, NULL, sessionType);
    printf("PairingSessionCreate type=%u status=%d session=%p\n", sessionType, status, session);
    if (status || !session) {
        return;
    }

    if (setFlags && flags) {
        status = setFlags(session, flags);
        printf("PairingSessionSetFlags flags=0x%llx status=%d\n", (unsigned long long)flags, status);
    }

    NSData *identifierData = [identifier dataUsingEncoding:NSUTF8StringEncoding];
    status = savePeer(session,
                      identifierData.bytes,
                      identifierData.length,
                      (const uint8_t *)publicKey.bytes);
    printf("PairingSessionSavePeer identifier=%s status=%d\n",
           identifier.UTF8String,
           status);

    if (findPeer) {
        uint8_t foundPublicKey[32] = {0};
        CFDictionaryRef acl = NULL;
        int32_t findStatus = findPeer(session,
                                      identifierData.bytes,
                                      identifierData.length,
                                      foundPublicKey,
                                      &acl);
        printf("PairingSessionFindPeer status=%d", findStatus);
        if (findStatus == 0) {
            NSData *found = [NSData dataWithBytes:foundPublicKey length:sizeof(foundPublicKey)];
            printf(" publicKey=%s", RedactedLength(found).UTF8String);
        }
        if (acl) {
            printf(" acl=%s", RedactedLength((__bridge id)acl).UTF8String);
            CFRelease(acl);
        }
        puts("");
    }

    if (invalidate) {
        invalidate(session);
    }
}

static void ProbeRPServerListen(NSTimeInterval seconds, NSString *serviceType, int passwordType, uint32_t pairSetupFlags) {
    LoadContinuityFrameworks();

    Class serverClass = NSClassFromString(@"RPServer");
    if (!serverClass) {
        fprintf(stderr, "RPServer not found\n");
        return;
    }

    id server = [[serverClass alloc] init];
    if (!server) {
        fprintf(stderr, "failed to create RPServer\n");
        return;
    }

    SEL setQueueSelector = @selector(setDispatchQueue:);
    if ([server respondsToSelector:setQueueSelector]) {
        typedef void (*SetQueueFn)(id, SEL, dispatch_queue_t);
        SetQueueFn fn = (SetQueueFn)[server methodForSelector:setQueueSelector];
        fn(server, setQueueSelector, dispatch_get_main_queue());
    }

    SEL setLabelSelector = @selector(setLabel:);
    if ([server respondsToSelector:setLabelSelector]) {
        typedef void (*SetObjectFn)(id, SEL, id);
        SetObjectFn fn = (SetObjectFn)[server methodForSelector:setLabelSelector];
        fn(server, setLabelSelector, @"macolinux-rpserver-probe");
    }

    SEL setServiceTypeSelector = @selector(setServiceType:);
    if (serviceType.length > 0 && [server respondsToSelector:setServiceTypeSelector]) {
        typedef void (*SetObjectFn)(id, SEL, id);
        SetObjectFn fn = (SetObjectFn)[server methodForSelector:setServiceTypeSelector];
        fn(server, setServiceTypeSelector, serviceType);
        printf("rpserver serviceType=%s\n", serviceType.UTF8String);
    }

    SEL setPasswordTypeSelector = @selector(setPasswordType:);
    if ([server respondsToSelector:setPasswordTypeSelector]) {
        typedef void (*SetIntFn)(id, SEL, int);
        SetIntFn fn = (SetIntFn)[server methodForSelector:setPasswordTypeSelector];
        fn(server, setPasswordTypeSelector, passwordType);
        printf("rpserver passwordType=%d\n", passwordType);
    }

    SEL setPairSetupFlagsSelector = @selector(setPairSetupFlags:);
    if ([server respondsToSelector:setPairSetupFlagsSelector]) {
        typedef void (*SetUIntFn)(id, SEL, uint32_t);
        SetUIntFn fn = (SetUIntFn)[server methodForSelector:setPairSetupFlagsSelector];
        fn(server, setPairSetupFlagsSelector, pairSetupFlags);
        printf("rpserver pairSetupFlags=0x%x\n", pairSetupFlags);
    }

    SEL setShowPasswordSelector = @selector(setShowPasswordHandler:);
    if ([server respondsToSelector:setShowPasswordSelector]) {
        id handler = ^(id password, unsigned int flags) {
            printf("rpserver show password: %s flags=0x%x\n",
                   RedactedLength(password).UTF8String,
                   flags);
        };
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[server methodForSelector:setShowPasswordSelector];
        fn(server, setShowPasswordSelector, [handler copy]);
    }

    SEL setHidePasswordSelector = @selector(setHidePasswordHandler:);
    if ([server respondsToSelector:setHidePasswordSelector]) {
        id handler = ^(unsigned int flags) {
            printf("rpserver hide password: flags=0x%x\n", flags);
        };
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[server methodForSelector:setHidePasswordSelector];
        fn(server, setHidePasswordSelector, [handler copy]);
    }

    SEL setPromptSelector = @selector(setPromptForPasswordHandler:);
    if ([server respondsToSelector:setPromptSelector]) {
        id handler = ^(int requestedPasswordType, unsigned int flags, int throttleSeconds) {
            printf("rpserver prompt password: type=%d flags=0x%x throttle=%d\n",
                   requestedPasswordType,
                   flags,
                   throttleSeconds);
        };
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[server methodForSelector:setPromptSelector];
        fn(server, setPromptSelector, [handler copy]);
    }

    SEL setErrorSelector = @selector(setErrorHandler:);
    if ([server respondsToSelector:setErrorSelector]) {
        id handler = ^(id error) {
            printf("rpserver error: %s\n", error ? [[error description] UTF8String] : "nil");
        };
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[server methodForSelector:setErrorSelector];
        fn(server, setErrorSelector, [handler copy]);
    }

    SEL setAcceptSelector = @selector(setAcceptHandler:);
    if ([server respondsToSelector:setAcceptSelector]) {
        id handler = ^(id session) {
            printf("rpserver accept session: class=%s description=%s\n",
                   session ? class_getName([session class]) : "nil",
                   RedactedLength(session).UTF8String);
        };
        typedef void (*SetHandlerFn)(id, SEL, id);
        SetHandlerFn fn = (SetHandlerFn)[server methodForSelector:setAcceptSelector];
        fn(server, setAcceptSelector, [handler copy]);
    }

    SEL activateSelector = @selector(activate);
    if (![server respondsToSelector:activateSelector]) {
        puts("RPServer activate unavailable");
        return;
    }
    typedef void (*VoidFn)(id, SEL);
    VoidFn activate = (VoidFn)[server methodForSelector:activateSelector];
    activate(server, activateSelector);
    puts("rpserver activated");

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
    while ([deadline timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }

    SEL invalidateSelector = @selector(invalidate);
    if ([server respondsToSelector:invalidateSelector]) {
        VoidFn invalidate = (VoidFn)[server methodForSelector:invalidateSelector];
        invalidate(server, invalidateSelector);
    }
}

static void PrintPairingSummary(void) {
    LoadContinuityFrameworks();

    Class managerClass = NSClassFromString(@"CUPairingManager");
    if (!managerClass) {
        fprintf(stderr, "CUPairingManager not found\n");
        return;
    }

    NSError *systemError = nil;
    id systemPairingID = nil;
    SEL copySystemSelector = @selector(copySystemPairingIdentifierAndReturnError:);
    if ([managerClass respondsToSelector:copySystemSelector]) {
        typedef id (*CopySystemFn)(id, SEL, NSError **);
        CopySystemFn fn = (CopySystemFn)[managerClass methodForSelector:copySystemSelector];
        systemPairingID = fn(managerClass, copySystemSelector, &systemError);
    }
    printf("system pairing identifier: %s\n", DescribeString(systemPairingID).UTF8String);
    if (systemError) {
        printf("system pairing identifier error: %s\n", systemError.description.UTF8String);
    }

    id manager = [[managerClass alloc] init];
    if ([manager respondsToSelector:@selector(setDispatchQueue:)]) {
        typedef void (*SetQueueFn)(id, SEL, dispatch_queue_t);
        SetQueueFn setQueue = (SetQueueFn)[manager methodForSelector:@selector(setDispatchQueue:)];
        setQueue(manager, @selector(setDispatchQueue:), dispatch_get_main_queue());
    }

    dispatch_semaphore_t identitySem = dispatch_semaphore_create(0);
    SEL identitySelector = @selector(getPairingIdentityWithOptions:completion:);
    if ([manager respondsToSelector:identitySelector]) {
        typedef void (*GetIdentityFn)(id, SEL, uint64_t, void (^)(id, NSError *));
        GetIdentityFn fn = (GetIdentityFn)[manager methodForSelector:identitySelector];
        fn(manager, identitySelector, 0, ^(id identity, NSError *error) {
            if (error) {
                printf("pairing identity error: %s\n", error.description.UTF8String);
            }
            PrintPairingIdentityShape(identity);
            dispatch_semaphore_signal(identitySem);
        });
        if (!WaitForSemaphore(identitySem, 5.0)) {
            puts("pairing identity timeout");
        }
    } else {
        puts("pairing identity: method unavailable");
    }

    dispatch_semaphore_t peersSem = dispatch_semaphore_create(0);
    SEL peersSelector = @selector(getPairedPeersWithOptions:completion:);
    if ([manager respondsToSelector:peersSelector]) {
        typedef void (*GetPeersFn)(id, SEL, uint64_t, void (^)(NSArray *, NSError *));
        GetPeersFn fn = (GetPeersFn)[manager methodForSelector:peersSelector];
        fn(manager, peersSelector, 0, ^(NSArray *peers, NSError *error) {
            if (error) {
                printf("paired peers error: %s\n", error.description.UTF8String);
            }
            printf("paired peers: %lu\n", (unsigned long)peers.count);
            NSUInteger index = 0;
            for (id peer in peers) {
                PrintPeerShape(peer, index++);
            }
            dispatch_semaphore_signal(peersSem);
        });
        if (!WaitForSemaphore(peersSem, 5.0)) {
            puts("paired peers timeout");
        }
    } else {
        puts("paired peers: method unavailable");
    }
}

static void Usage(const char *argv0) {
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  %s classes [FILTER]\n", argv0);
    fprintf(stderr, "  %s class CLASSNAME\n", argv0);
    fprintf(stderr, "  %s class-imps CLASSNAME [FILTER]\n", argv0);
    fprintf(stderr, "  %s methods FILTER\n", argv0);
    fprintf(stderr, "  %s protocol PROTOCOLNAME\n", argv0);
    fprintf(stderr, "  %s pairing-summary\n", argv0);
    fprintf(stderr, "  %s keychain-summary\n", argv0);
    fprintf(stderr, "  %s sec-spake [CLIENT_ID] [SERVER_ID] [SCHEME]\n", argv0);
    fprintf(stderr, "  %s sec-spake-client CONTEXT CLIENT_ID SERVER_ID PASSWORD\n", argv0);
    fprintf(stderr, "  %s sec-spake-server CONTEXT CLIENT_ID SERVER_ID SERVER_VERIFIER_HEX REGISTRATION_RECORD_HEX\n", argv0);
    fprintf(stderr, "  %s coreutils-symbols\n", argv0);
    fprintf(stderr, "  %s auth-types [MAX_TYPE]\n", argv0);
    fprintf(stderr, "  %s save-peer PEER_JSON [OPTIONS]\n", argv0);
    fprintf(stderr, "  %s capi-save-peer PEER_JSON [SESSION_TYPE] [FLAGS]\n", argv0);
    fprintf(stderr, "  %s rpidentity-peer PEER_JSON [MAX_TYPE]\n", argv0);
    fprintf(stderr, "  %s rpclient-list-identities [FLAGS]\n", argv0);
    fprintf(stderr, "  %s rpclient-add-identity PEER_JSON [TYPE] [SOURCE]\n", argv0);
    fprintf(stderr, "  %s rpclient-add-identity-nosource PEER_JSON [TYPE]\n", argv0);
    fprintf(stderr, "  %s rpclient-diagnostic-command COMMAND [JSON|@PATH|-]\n", argv0);
    fprintf(stderr, "  %s rpclient-endpoint-map APPLICATION_SERVICE DEVICE_ID ENDPOINT_ID\n", argv0);
    fprintf(stderr, "  %s rpclient-internal-map TYPE APPLICATION_SERVICE DEVICE_ID ENDPOINT_ID\n", argv0);
    fprintf(stderr, "  %s rpclient-listener-map LISTENER_ID DEVICE_ID\n", argv0);
    fprintf(stderr, "  %s rpclient-query-listener-map LISTENER_ID DEVICE_ID\n", argv0);
    fprintf(stderr, "  %s rpclient-auto-map on|off\n", argv0);
    fprintf(stderr, "  %s rpcl-browse [SERVICE_TYPE] [SECONDS] [FLAGS] [CONTROL_FLAGS] [USE_CASE]\n", argv0);
    fprintf(stderr, "  %s rp-pairing-listen [SECONDS] [visible]\n", argv0);
    fprintf(stderr, "  %s rd-pairing-server [SECONDS]\n", argv0);
    fprintf(stderr, "  %s rpserver-listen [SECONDS] [SERVICE_TYPE] [PASSWORD_TYPE] [PAIR_SETUP_FLAGS]\n", argv0);
    fprintf(stderr, "  %s nw-appsvc-descriptor [SERVICE]\n", argv0);
    fprintf(stderr, "  %s nw-appsvc-browse SERVICE [BUNDLE_ID] [SECONDS]\n", argv0);
    fprintf(stderr, "  %s nw-appsvc-listen SERVICE [BUNDLE_ID] [SECONDS]\n", argv0);
    fprintf(stderr, "  %s nw-appsvc-browse-custom SERVICE BUNDLE_ID CUSTOM_DATA [SECONDS]\n", argv0);
    fprintf(stderr, "  %s nw-appsvc-listen-custom SERVICE BUNDLE_ID CUSTOM_DATA [SECONDS]\n", argv0);
    fprintf(stderr, "    CUSTOM_DATA accepts @path, hex:001122, json:{...}, or a literal UTF-8 string\n");
    fprintf(stderr, "  %s nw-appsvc-browse-pairing SERVICE BUNDLE_ID [SECONDS]\n", argv0);
    fprintf(stderr, "  %s nw-appsvc-listen-pairing SERVICE BUNDLE_ID [PIN] [SECONDS]\n", argv0);
    fprintf(stderr, "\n");
    fprintf(stderr, "This tool is read-only and redacts keychain/private-key values by default.\n");
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        setvbuf(stdout, NULL, _IOLBF, 0);
        if (argc < 2) {
            Usage(argv[0]);
            return 2;
        }

        NSString *command = [NSString stringWithUTF8String:argv[1]];
        if ([command isEqualToString:@"classes"]) {
            NSString *filter = argc >= 3 ? [NSString stringWithUTF8String:argv[2]] : @"";
            PrintClassList(filter);
            return 0;
        }
        if ([command isEqualToString:@"class"] && argc == 3) {
            PrintClassInfo([NSString stringWithUTF8String:argv[2]]);
            return 0;
        }
        if ([command isEqualToString:@"class-imps"] && argc >= 3) {
            NSString *filter = argc >= 4 ? [NSString stringWithUTF8String:argv[3]] : @"";
            PrintClassIMPs([NSString stringWithUTF8String:argv[2]], filter);
            return 0;
        }
        if ([command isEqualToString:@"methods"] && argc == 3) {
            PrintMethodSearch([NSString stringWithUTF8String:argv[2]]);
            return 0;
        }
        if ([command isEqualToString:@"protocol"] && argc == 3) {
            PrintProtocolInfo([NSString stringWithUTF8String:argv[2]]);
            return 0;
        }
        if ([command isEqualToString:@"pairing-summary"]) {
            PrintPairingSummary();
            return 0;
        }
        if ([command isEqualToString:@"keychain-summary"]) {
            PrintKeychainSummary();
            return 0;
        }
        if ([command isEqualToString:@"sec-spake"]) {
            NSString *clientIdentity = argc >= 3 ? [NSString stringWithUTF8String:argv[2]] : @"fistel";
            NSString *serverIdentity = argc >= 4 ? [NSString stringWithUTF8String:argv[3]] : @"endor";
            unsigned short scheme = argc >= 5 ? (unsigned short)strtoul(argv[4], NULL, 0) : 1;
            ProbeSecuritySPAKE(clientIdentity, serverIdentity, scheme);
            return 0;
        }
        if ([command isEqualToString:@"sec-spake-client"] && argc == 6) {
            CreateClientSPAKEIdentity([NSString stringWithUTF8String:argv[2]],
                                      [NSString stringWithUTF8String:argv[3]],
                                      [NSString stringWithUTF8String:argv[4]],
                                      [NSString stringWithUTF8String:argv[5]]);
            return 0;
        }
        if ([command isEqualToString:@"sec-spake-server"] && argc == 7) {
            NSString *serverPasswordVerifier = [NSString stringWithUTF8String:argv[5]];
            NSString *registrationRecord = [NSString stringWithUTF8String:argv[6]];
            if (![serverPasswordVerifier hasPrefix:@"hex:"]) {
                serverPasswordVerifier = [@"hex:" stringByAppendingString:serverPasswordVerifier];
            }
            if (![registrationRecord hasPrefix:@"hex:"]) {
                registrationRecord = [@"hex:" stringByAppendingString:registrationRecord];
            }
            CreateServerSPAKEIdentity([NSString stringWithUTF8String:argv[2]],
                                      [NSString stringWithUTF8String:argv[3]],
                                      [NSString stringWithUTF8String:argv[4]],
                                      serverPasswordVerifier,
                                      registrationRecord);
            return 0;
        }
        if ([command isEqualToString:@"coreutils-symbols"]) {
            ProbeCoreUtilsSymbols();
            return 0;
        }
        if ([command isEqualToString:@"auth-types"]) {
            NSUInteger maxType = argc >= 3 ? (NSUInteger)strtoul(argv[2], NULL, 0) : 16;
            ProbeAuthenticationTypes(maxType);
            return 0;
        }
        if ([command isEqualToString:@"save-peer"] && argc >= 3) {
            uint64_t options = argc >= 4 ? strtoull(argv[3], NULL, 0) : 0;
            TrySavePeer([NSString stringWithUTF8String:argv[2]], options);
            return 0;
        }
        if ([command isEqualToString:@"capi-save-peer"] && argc >= 3) {
            uint32_t sessionType = argc >= 4 ? (uint32_t)strtoul(argv[3], NULL, 0) : 0;
            uint64_t flags = argc >= 5 ? strtoull(argv[4], NULL, 0) : 0;
            TryPairingSessionSavePeer([NSString stringWithUTF8String:argv[2]], sessionType, flags);
            return 0;
        }
        if ([command isEqualToString:@"rpidentity-peer"] && argc >= 3) {
            NSUInteger maxType = argc >= 4 ? (NSUInteger)strtoul(argv[3], NULL, 0) : 12;
            TryRPIdentityFromPeer([NSString stringWithUTF8String:argv[2]], maxType);
            return 0;
        }
        if ([command isEqualToString:@"rpclient-list-identities"]) {
            uint32_t flags = argc >= 3 ? (uint32_t)strtoul(argv[2], NULL, 0) : 0xffffffff;
            TryRPClientListIdentities(flags);
            return 0;
        }
        if ([command isEqualToString:@"rpclient-add-identity"] && argc >= 3) {
            int type = argc >= 4 ? (int)strtol(argv[3], NULL, 0) : 13;
            int source = argc >= 5 ? (int)strtol(argv[4], NULL, 0) : 0;
            TryRPClientAddIdentity([NSString stringWithUTF8String:argv[2]], type, source, YES);
            return 0;
        }
        if ([command isEqualToString:@"rpclient-add-identity-nosource"] && argc >= 3) {
            int type = argc >= 4 ? (int)strtol(argv[3], NULL, 0) : 13;
            TryRPClientAddIdentity([NSString stringWithUTF8String:argv[2]], type, 0, NO);
            return 0;
        }
        if ([command isEqualToString:@"rpclient-diagnostic-command"] && argc >= 3) {
            id params = argc >= 4 ? JSONValueFromArgument([NSString stringWithUTF8String:argv[3]]) : @{};
            if (!params) {
                return 1;
            }
            TryRPClientDiagnosticCommand([NSString stringWithUTF8String:argv[2]], params);
            return 0;
        }
        if ([command isEqualToString:@"rpclient-endpoint-map"] && argc >= 5) {
            TryRPClientEndpointMapping([NSString stringWithUTF8String:argv[2]],
                                       [NSString stringWithUTF8String:argv[3]],
                                       [NSString stringWithUTF8String:argv[4]]);
            return 0;
        }
        if ([command isEqualToString:@"rpclient-internal-map"] && argc >= 6) {
            int mappingType = (int)strtol(argv[2], NULL, 0);
            TryRPClientInternalDeviceMapping(mappingType,
                                             [NSString stringWithUTF8String:argv[3]],
                                             [NSString stringWithUTF8String:argv[4]],
                                             [NSString stringWithUTF8String:argv[5]]);
            return 0;
        }
        if ([command isEqualToString:@"rpclient-listener-map"] && argc >= 4) {
            TryRPClientDeviceToListenerMapping([NSString stringWithUTF8String:argv[2]],
                                               [NSString stringWithUTF8String:argv[3]]);
            return 0;
        }
        if ([command isEqualToString:@"rpclient-query-listener-map"] && argc >= 4) {
            TryRPClientQueryDeviceToListenerMapping([NSString stringWithUTF8String:argv[2]],
                                                    [NSString stringWithUTF8String:argv[3]]);
            return 0;
        }
        if ([command isEqualToString:@"rpclient-auto-map"] && argc >= 3) {
            BOOL enabled = strcmp(argv[2], "on") == 0 || strcmp(argv[2], "1") == 0 || strcmp(argv[2], "true") == 0;
            TryRPClientSetAutoMapping(enabled);
            return 0;
        }
        if ([command isEqualToString:@"rpcl-browse"]) {
            NSString *serviceType = argc >= 3 ? [NSString stringWithUTF8String:argv[2]] : @"com.apple.universalcontrol";
            NSTimeInterval seconds = argc >= 4 ? strtod(argv[3], NULL) : 8.0;
            uint32_t flags = argc >= 5 ? (uint32_t)strtoul(argv[4], NULL, 0) : 0;
            uint64_t controlFlags = argc >= 6 ? strtoull(argv[5], NULL, 0) : 0;
            uint32_t useCase = argc >= 7 ? (uint32_t)strtoul(argv[6], NULL, 0) : 0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            TryRPCompanionLinkBrowse(serviceType, seconds, flags, controlFlags, useCase);
            return 0;
        }
        if ([command isEqualToString:@"rp-pairing-listen"]) {
            NSTimeInterval seconds = argc >= 3 ? strtod(argv[2], NULL) : 10.0;
            BOOL uiVisible = argc >= 4 && strcmp(argv[3], "visible") == 0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            ProbeRPPairingListen(seconds, uiVisible);
            return 0;
        }
        if ([command isEqualToString:@"rd-pairing-server"]) {
            NSTimeInterval seconds = argc >= 3 ? strtod(argv[2], NULL) : 10.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            ProbeRemoteDisplayPairingServer(seconds);
            return 0;
        }
        if ([command isEqualToString:@"rpserver-listen"]) {
            NSTimeInterval seconds = argc >= 3 ? strtod(argv[2], NULL) : 10.0;
            NSString *serviceType = argc >= 4 ? [NSString stringWithUTF8String:argv[3]] : @"";
            int passwordType = argc >= 5 ? (int)strtol(argv[4], NULL, 0) : 10;
            uint32_t pairSetupFlags = argc >= 6 ? (uint32_t)strtoul(argv[5], NULL, 0) : 0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            ProbeRPServerListen(seconds, serviceType, passwordType, pairSetupFlags);
            return 0;
        }
        if ([command isEqualToString:@"nw-appsvc-descriptor"]) {
            NSString *serviceName = argc >= 3 ? [NSString stringWithUTF8String:argv[2]] : @"com.apple.macolinux.probe";
            DumpNetworkApplicationServiceDescriptors(serviceName);
            return 0;
        }
        if ([command isEqualToString:@"nw-appsvc-browse"] && argc >= 3) {
            NSString *serviceName = [NSString stringWithUTF8String:argv[2]];
            NSString *bundleID = argc >= 4 ? [NSString stringWithUTF8String:argv[3]] : @"";
            NSTimeInterval seconds = argc >= 5 ? strtod(argv[4], NULL) : 8.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            RunNetworkApplicationServiceBrowse(serviceName, bundleID, seconds, nil);
            return 0;
        }
        if ([command isEqualToString:@"nw-appsvc-listen"] && argc >= 3) {
            NSString *serviceName = [NSString stringWithUTF8String:argv[2]];
            NSString *bundleID = argc >= 4 ? [NSString stringWithUTF8String:argv[3]] : @"";
            NSTimeInterval seconds = argc >= 5 ? strtod(argv[4], NULL) : 8.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            RunNetworkApplicationServiceListen(serviceName, bundleID, seconds, nil);
            return 0;
        }
        if ([command isEqualToString:@"nw-appsvc-browse-custom"] && argc >= 5) {
            NSString *serviceName = [NSString stringWithUTF8String:argv[2]];
            NSString *bundleID = [NSString stringWithUTF8String:argv[3]];
            NSData *customService = DataFromProbeArgument([NSString stringWithUTF8String:argv[4]]);
            if (!customService) {
                return 1;
            }
            NSTimeInterval seconds = argc >= 6 ? strtod(argv[5], NULL) : 8.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            RunNetworkApplicationServiceBrowse(serviceName, bundleID, seconds, customService);
            return 0;
        }
        if ([command isEqualToString:@"nw-appsvc-listen-custom"] && argc >= 5) {
            NSString *serviceName = [NSString stringWithUTF8String:argv[2]];
            NSString *bundleID = [NSString stringWithUTF8String:argv[3]];
            NSData *customService = DataFromProbeArgument([NSString stringWithUTF8String:argv[4]]);
            if (!customService) {
                return 1;
            }
            NSTimeInterval seconds = argc >= 6 ? strtod(argv[5], NULL) : 8.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            RunNetworkApplicationServiceListen(serviceName, bundleID, seconds, customService);
            return 0;
        }
        if ([command isEqualToString:@"nw-appsvc-browse-pairing"] && argc >= 4) {
            NSString *serviceName = [NSString stringWithUTF8String:argv[2]];
            NSString *bundleID = [NSString stringWithUTF8String:argv[3]];
            NSTimeInterval seconds = argc >= 5 ? strtod(argv[4], NULL) : 8.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            RunNetworkApplicationServiceBrowse(serviceName, bundleID, seconds, BrowserPinPairingCustomService());
            return 0;
        }
        if ([command isEqualToString:@"nw-appsvc-listen-pairing"] && argc >= 4) {
            NSString *serviceName = [NSString stringWithUTF8String:argv[2]];
            NSString *bundleID = [NSString stringWithUTF8String:argv[3]];
            NSString *pin = argc >= 5 ? [NSString stringWithUTF8String:argv[4]] : @"123456";
            NSTimeInterval seconds = argc >= 6 ? strtod(argv[5], NULL) : 8.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }
            RunNetworkApplicationServiceListen(serviceName, bundleID, seconds, ListenerPinPairingCustomService(pin));
            return 0;
        }

        Usage(argv[0]);
        return 2;
    }
}
