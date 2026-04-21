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
    return initFn(identity, initSelector, peer, type);
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

static void TryRPClientAddIdentity(NSString *jsonPath, int type, int source) {
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

    SEL selector = @selector(addOrUpdateIdentity:source:completion:);
    if (![client respondsToSelector:selector]) {
        puts("addOrUpdateIdentity:source:completion: unavailable");
        return;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    typedef void (*AddIdentityFn)(id, SEL, id, int, void (^)(NSError *));
    AddIdentityFn addIdentity = (AddIdentityFn)[client methodForSelector:selector];
    addIdentity(client, selector, identity, source, ^(NSError *error) {
        if (error) {
            printf("addOrUpdateIdentity error: %s\n", error.description.UTF8String);
        } else {
            puts("addOrUpdateIdentity completed without error");
        }
        dispatch_semaphore_signal(sem);
    });
    if (!WaitForSemaphore(sem, 5.0)) {
        puts("addOrUpdateIdentity timeout");
    }
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
    fprintf(stderr, "  %s methods FILTER\n", argv0);
    fprintf(stderr, "  %s protocol PROTOCOLNAME\n", argv0);
    fprintf(stderr, "  %s pairing-summary\n", argv0);
    fprintf(stderr, "  %s keychain-summary\n", argv0);
    fprintf(stderr, "  %s coreutils-symbols\n", argv0);
    fprintf(stderr, "  %s auth-types [MAX_TYPE]\n", argv0);
    fprintf(stderr, "  %s save-peer PEER_JSON [OPTIONS]\n", argv0);
    fprintf(stderr, "  %s capi-save-peer PEER_JSON [SESSION_TYPE] [FLAGS]\n", argv0);
    fprintf(stderr, "  %s rpidentity-peer PEER_JSON [MAX_TYPE]\n", argv0);
    fprintf(stderr, "  %s rpclient-list-identities [FLAGS]\n", argv0);
    fprintf(stderr, "  %s rpclient-add-identity PEER_JSON [TYPE] [SOURCE]\n", argv0);
    fprintf(stderr, "  %s rp-pairing-listen [SECONDS] [visible]\n", argv0);
    fprintf(stderr, "  %s rd-pairing-server [SECONDS]\n", argv0);
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
            TryRPClientAddIdentity([NSString stringWithUTF8String:argv[2]], type, source);
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

        Usage(argv[0]);
        return 2;
    }
}
