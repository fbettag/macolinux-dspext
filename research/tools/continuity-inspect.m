#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <dispatch/dispatch.h>
#import <objc/runtime.h>

static NSArray<NSString *> *FrameworkPaths(void) {
    return @[
        @"/System/Library/PrivateFrameworks/CoreUtils.framework/CoreUtils",
        @"/System/Library/PrivateFrameworks/Rapport.framework/Rapport",
        @"/System/Library/PrivateFrameworks/Sharing.framework/Sharing",
        @"/System/Library/PrivateFrameworks/IDS.framework/IDS",
        @"/System/Library/PrivateFrameworks/IDSFoundation.framework/IDSFoundation"
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

static void PrintMethods(Class cls, BOOL meta) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(meta ? object_getClass(cls) : cls, &count);
    printf("%s methods (%u):\n", meta ? "class" : "instance", count);
    for (unsigned int i = 0; i < count; i++) {
        SEL selector = method_getName(methods[i]);
        const char *types = method_getTypeEncoding(methods[i]);
        printf("  %c[%s %s] %s\n",
               meta ? '+' : '-',
               class_getName(cls),
               sel_getName(selector),
               types ? types : "");
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
    PrintMethods(cls, NO);
    PrintMethods(cls, YES);
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
        while (dispatch_semaphore_wait(identitySem, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) != 0) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
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
        while (dispatch_semaphore_wait(peersSem, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) != 0) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }
    } else {
        puts("paired peers: method unavailable");
    }
}

static void Usage(const char *argv0) {
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  %s classes [FILTER]\n", argv0);
    fprintf(stderr, "  %s class CLASSNAME\n", argv0);
    fprintf(stderr, "  %s pairing-summary\n", argv0);
    fprintf(stderr, "  %s keychain-summary\n", argv0);
    fprintf(stderr, "\n");
    fprintf(stderr, "This tool is read-only and redacts keychain/private-key values by default.\n");
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
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
        if ([command isEqualToString:@"pairing-summary"]) {
            PrintPairingSummary();
            return 0;
        }
        if ([command isEqualToString:@"keychain-summary"]) {
            PrintKeychainSummary();
            return 0;
        }

        Usage(argv[0]);
        return 2;
    }
}
