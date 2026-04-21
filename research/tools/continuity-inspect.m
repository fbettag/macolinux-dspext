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
    fprintf(stderr, "  %s protocol PROTOCOLNAME\n", argv0);
    fprintf(stderr, "  %s pairing-summary\n", argv0);
    fprintf(stderr, "  %s keychain-summary\n", argv0);
    fprintf(stderr, "  %s auth-types [MAX_TYPE]\n", argv0);
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
        if ([command isEqualToString:@"auth-types"]) {
            NSUInteger maxType = argc >= 3 ? (NSUInteger)strtoul(argv[2], NULL, 0) : 16;
            ProbeAuthenticationTypes(maxType);
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
