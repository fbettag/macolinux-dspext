#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <dispatch/dispatch.h>
#import <errno.h>
#import <netdb.h>
#import <poll.h>
#import <stdint.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <unistd.h>

static NSArray<NSString *> *FrameworkPaths(void) {
    return @[
        @"/System/Library/PrivateFrameworks/Sharing.framework/Sharing",
        @"/System/Library/PrivateFrameworks/CoreUtils.framework/CoreUtils",
        @"/System/Library/PrivateFrameworks/Rapport.framework/Rapport",
        @"/System/Library/PrivateFrameworks/IDS.framework/IDS",
        @"/System/Library/PrivateFrameworks/IDSFoundation.framework/IDSFoundation",
    ];
}

static void LoadFrameworks(void) {
    for (NSString *path in FrameworkPaths()) {
        void *handle = dlopen(path.UTF8String, RTLD_NOW | RTLD_LOCAL);
        printf("%-13s %s\n", handle ? "loaded" : "missing", path.UTF8String);
    }
}

static NSString *SafeString(id object) {
    if (!object) {
        return @"nil";
    }
    NSString *description = [object description];
    return description ?: NSStringFromClass([object class]);
}

static void PrintMethodList(Class cls, const char *label) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    printf("%s.method_count=%u\n", label, count);
    for (unsigned int i = 0; i < count; i++) {
        printf("%s.method[%u]=%s\n", label, i, sel_getName(method_getName(methods[i])));
    }
    free(methods);
}

static void PrintInterfaceDescription(Class cls, SEL selector, const char *label) {
    if (!cls || ![cls respondsToSelector:selector]) {
        printf("%s.available=false\n", label);
        return;
    }
    typedef id (*ClassGetter)(id, SEL);
    ClassGetter getter = (ClassGetter)[cls methodForSelector:selector];
    id value = getter ? getter(cls, selector) : nil;
    printf("%s.selector=%s\n", label, sel_getName(selector));
    printf("%s.class=%s\n", label, value ? class_getName([value class]) : "nil");
    printf("%s.value=%s\n", label, SafeString(value).UTF8String);
    if (value) {
        printf("%s.debug=%s\n", label, [[value debugDescription] UTF8String]);
    }
}

static id DecodedServiceMessage(id service) {
    if (![service respondsToSelector:@selector(messageData)]) {
        return nil;
    }
    typedef id (*GetterFn)(id, SEL);
    GetterFn fn = (GetterFn)[service methodForSelector:@selector(messageData)];
    id messageData = fn(service, @selector(messageData));
    if (![messageData isKindOfClass:[NSData class]]) {
        return messageData;
    }
    NSError *error = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:messageData
                                                        options:NSPropertyListImmutable
                                                         format:nil
                                                          error:&error];
    if (!plist) {
        printf("messageData.decode.error=%s\n", SafeString(error).UTF8String);
        return messageData;
    }
    return plist;
}

static void PrintDecodedValue(id value, const char *label) {
    printf("%s.class=%s\n", label, value ? class_getName([value class]) : "nil");
    printf("%s.value=%s\n", label, SafeString(value).UTF8String);
    if ([value isKindOfClass:[NSDictionary class]]) {
        NSData *authorData = value[@"author_data"];
        if ([authorData isKindOfClass:[NSData class]]) {
            NSError *error = nil;
            id author = [NSPropertyListSerialization propertyListWithData:authorData
                                                                  options:NSPropertyListImmutable
                                                                   format:nil
                                                                    error:&error];
            printf("%s.author_data.decoded.class=%s\n", label, author ? class_getName([author class]) : "nil");
            printf("%s.author_data.decoded.value=%s\n", label, SafeString(author ?: error).UTF8String);
        }
    }
}

static void PrintBinaryPlistBase64(id value, const char *label) {
    if (!value) {
        printf("%s.plist_b64=nil\n", label);
        return;
    }
    NSError *error = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:value
                                                              format:NSPropertyListBinaryFormat_v1_0
                                                             options:0
                                                               error:&error];
    if (!data) {
        printf("%s.plist_error=%s\n", label, SafeString(error).UTF8String);
        return;
    }
    printf("%s.plist_length=%lu\n", label, (unsigned long)data.length);
    printf("%s.plist_b64=%s\n", label, [data base64EncodedStringWithOptions:0].UTF8String);
}

static void WriteCStringToFileHandle(NSFileHandle *fileHandle, const char *bytes, const char *label) {
    if (!fileHandle || !bytes || !bytes[0]) {
        return;
    }
    NSData *data = [NSData dataWithBytes:bytes length:strlen(bytes)];
    @try {
        [fileHandle writeData:data];
        printf("%s.write.bytes=%lu\n", label, (unsigned long)data.length);
    } @catch (NSException *exception) {
        printf("%s.write.exception=%s\n", label, SafeString(exception).UTF8String);
    }
}

static void PollReadFileHandle(NSFileHandle *fileHandle, int timeoutMs, const char *label) {
    if (!fileHandle) {
        return;
    }
    int fd = [fileHandle fileDescriptor];
    if (fd < 0) {
        printf("%s.read.fd=-1\n", label);
        return;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    int rc = poll(&pfd, 1, timeoutMs);
    printf("%s.read.poll=%d revents=0x%x\n", label, rc, rc > 0 ? pfd.revents : 0);
    if (rc <= 0 || !(pfd.revents & POLLIN)) {
        return;
    }
    uint8_t buffer[4096];
    ssize_t n = read(fd, buffer, sizeof(buffer));
    printf("%s.read.bytes=%zd\n", label, n);
    if (n > 0) {
        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)n];
        NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        printf("%s.read.hex=%s\n", label, [[data description] UTF8String]);
        printf("%s.read.utf8=%s\n", label, SafeString(text).UTF8String);
    }
}

static BOOL WriteAll(int fd, const uint8_t *buffer, ssize_t length) {
    ssize_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, buffer + offset, (size_t)(length - offset));
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NO;
        }
        if (written == 0) {
            return NO;
        }
        offset += written;
    }
    return YES;
}

static int ConnectRelaySocket(const char *spec, const char *label) {
    if (!spec || !spec[0]) {
        return -1;
    }
    const char *colon = strrchr(spec, ':');
    if (!colon || colon == spec || !colon[1]) {
        printf("%s.relay.error=expected HOST:PORT\n", label);
        return -1;
    }

    char host[256];
    size_t hostLen = (size_t)(colon - spec);
    if (hostLen >= sizeof(host)) {
        printf("%s.relay.error=host too long\n", label);
        return -1;
    }
    memcpy(host, spec, hostLen);
    host[hostLen] = '\0';
    const char *port = colon + 1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *results = NULL;
    int gai = getaddrinfo(host, port, &hints, &results);
    if (gai != 0) {
        printf("%s.relay.getaddrinfo.error=%s\n", label, gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *it = results; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(results);

    if (fd < 0) {
        printf("%s.relay.connect.error=%s\n", label, strerror(errno));
        return -1;
    }
    printf("%s.relay.connected=%s\n", label, spec);
    return fd;
}

static void PumpFd(int fromFd, int toFd, const char *label) {
    uint8_t buffer[16384];
    uint64_t total = 0;
    for (;;) {
        ssize_t n = read(fromFd, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            printf("%s.relay.read_error=%s\n", label, strerror(errno));
            break;
        }
        if (n == 0) {
            break;
        }
        if (!WriteAll(toFd, buffer, n)) {
            printf("%s.relay.write_error=%s\n", label, strerror(errno));
            break;
        }
        total += (uint64_t)n;
    }
    printf("%s.relay.closed.bytes=%llu\n", label, (unsigned long long)total);
    shutdown(toFd, SHUT_WR);
    close(fromFd);
    close(toFd);
}

static void StartRelay(NSFileHandle *fileHandle, const char *spec, const char *label) {
    if (!fileHandle || !spec || !spec[0]) {
        return;
    }
    int streamFd = [fileHandle fileDescriptor];
    if (streamFd < 0) {
        printf("%s.relay.stream_fd=-1\n", label);
        return;
    }
    int relayFd = ConnectRelaySocket(spec, label);
    if (relayFd < 0) {
        return;
    }

    int streamReadFd = dup(streamFd);
    int streamWriteFd = dup(streamFd);
    int relayReadFd = dup(relayFd);
    int relayWriteFd = dup(relayFd);
    close(relayFd);
    if (streamReadFd < 0 || streamWriteFd < 0 || relayReadFd < 0 || relayWriteFd < 0) {
        printf("%s.relay.dup_error=%s\n", label, strerror(errno));
        if (streamReadFd >= 0) {
            close(streamReadFd);
        }
        if (streamWriteFd >= 0) {
            close(streamWriteFd);
        }
        if (relayReadFd >= 0) {
            close(relayReadFd);
        }
        if (relayWriteFd >= 0) {
            close(relayWriteFd);
        }
        return;
    }

    NSFileHandle *retainedHandle = fileHandle;
    NSString *streamToRelay = [NSString stringWithFormat:@"%s.stream_to_relay", label];
    NSString *relayToStream = [NSString stringWithFormat:@"%s.relay_to_stream", label];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        (void)retainedHandle;
        PumpFd(streamReadFd, relayWriteFd, streamToRelay.UTF8String);
    });
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        (void)retainedHandle;
        PumpFd(relayReadFd, streamWriteFd, relayToStream.UTF8String);
    });
}

static NSUserActivity *StartUserActivity(NSString *activityType, NSString *managerID) {
    NSUserActivity *activity = [[NSUserActivity alloc] initWithActivityType:activityType];
    activity.title = [NSString stringWithFormat:@"macolinux stream %@", activityType];
    activity.userInfo = @{
        @"SDStreamActivityIdentifier": activityType,
        @"manager_id": managerID ?: @"",
        @"source": @"macolinux-dspext-probe",
    };
    if ([activity respondsToSelector:@selector(setEligibleForHandoff:)]) {
        activity.eligibleForHandoff = YES;
    }
    if ([activity respondsToSelector:@selector(setEligibleForSearch:)]) {
        activity.eligibleForSearch = NO;
    }
    if ([activity respondsToSelector:@selector(setEligibleForPublicIndexing:)]) {
        activity.eligibleForPublicIndexing = NO;
    }
    if ([activity respondsToSelector:@selector(setNeedsSave:)]) {
        activity.needsSave = YES;
    }
    [activity becomeCurrent];
    printf("activity.started=true\n");
    printf("activity.type=%s\n", activityType.UTF8String);
    printf("activity.value=%s\n", SafeString(activity).UTF8String);
    return activity;
}

static void SetObjectProperty(id object, NSString *selectorName, id value) {
    SEL selector = NSSelectorFromString(selectorName);
    if (!object || !value || ![object respondsToSelector:selector]) {
        return;
    }
    typedef void (*SetterFn)(id, SEL, id);
    SetterFn fn = (SetterFn)[object methodForSelector:selector];
    if (fn) {
        fn(object, selector, value);
    }
}

static void ConfigureService(id service, NSString *managerID, NSString *serviceName, BOOL fillPeerFields) {
    SetObjectProperty(service, @"setManagerID:", managerID);
    SetObjectProperty(service, @"setServiceType:", serviceName);
    if (!fillPeerFields) {
        return;
    }
    NSString *hostName = [[NSHost currentHost] localizedName] ?: [[NSHost currentHost] name] ?: @"endor";
    const char *bonjourName = getenv("UC_BONJOUR_NAME");
    NSString *deviceID = bonjourName && bonjourName[0]
        ? [NSString stringWithUTF8String:bonjourName]
        : [[NSUUID UUID] UUIDString];
    SetObjectProperty(service, @"setDeviceName:", hostName);
    SetObjectProperty(service, @"setDeviceID:", deviceID);
    SetObjectProperty(service, @"setIpAddress:", @"127.0.0.1");
    SetObjectProperty(service, @"setNsxpcVersion:", @1);
}

@interface ProbeClient : NSObject
@property (nonatomic, assign) NSUInteger eventCount;
@end

@implementation ProbeClient

- (void)updatedFoundDeviceList:(NSArray *)devices {
    self.eventCount += 1;
    printf("client.updatedFoundDeviceList count=%lu devices=%s\n",
           (unsigned long)self.eventCount,
           SafeString(devices).UTF8String);
}

- (void)interrupted {
    self.eventCount += 1;
    printf("client.interrupted count=%lu\n", (unsigned long)self.eventCount);
}

- (void)invalidated {
    self.eventCount += 1;
    printf("client.invalidated count=%lu\n", (unsigned long)self.eventCount);
}

- (void)streamToService:(id)service withFileHandle:(NSFileHandle *)fileHandle acceptReply:(void (^)(BOOL))reply {
    self.eventCount += 1;
    printf("client.streamToService count=%lu\n", (unsigned long)self.eventCount);
    printf("client.stream.service.class=%s\n", service ? class_getName([service class]) : "nil");
    printf("client.stream.service.value=%s\n", SafeString(service).UTF8String);
    printf("client.stream.fileHandle.class=%s\n", fileHandle ? class_getName([fileHandle class]) : "nil");
    printf("client.stream.fileHandle.value=%s\n", SafeString(fileHandle).UTF8String);
    if (reply) {
        printf("client.stream.accept=true\n");
        reply(YES);
    }
    const char *relay = getenv("UC_STREAM_RELAY");
    if (relay && relay[0]) {
        StartRelay(fileHandle, relay, "client.stream");
    } else {
        WriteCStringToFileHandle(fileHandle, getenv("UC_STREAM_REPLY"), "client.stream");
        PollReadFileHandle(fileHandle, 1000, "client.stream");
    }
}

@end

static void Usage(const char *argv0) {
    fprintf(stderr, "usage: %s describe | proxy IDENTIFIER [SECONDS] | enable IDENTIFIER SERVICE_NAME [SECONDS] | enable-full IDENTIFIER SERVICE_NAME [SECONDS] | enable-activity IDENTIFIER SERVICE_NAME [SECONDS] | enable-full-activity IDENTIFIER SERVICE_NAME [SECONDS] | message SERVICE_NAME | message-full IDENTIFIER SERVICE_NAME | connect-b64 PLIST_B64 [SECONDS] | loopback IDENTIFIER SERVICE_NAME [SECONDS]\n", argv0);
    exit(2);
}

static BOOL WaitForSemaphore(dispatch_semaphore_t sem, NSTimeInterval seconds) {
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC));
    return dispatch_semaphore_wait(sem, timeout) == 0;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        setvbuf(stdout, NULL, _IOLBF, 0);
        LoadFrameworks();

        if (argc < 2) {
            Usage(argv[0]);
        }

        NSString *command = [NSString stringWithUTF8String:argv[1]];
        Class managerClass = NSClassFromString(@"SFCompanionXPCManager");
        if (!managerClass) {
            fprintf(stderr, "SFCompanionXPCManager not found\n");
            return 1;
        }

        if ([command isEqualToString:@"describe"]) {
            PrintInterfaceDescription(managerClass, @selector(xpcManagerInterface), "xpcManagerInterface");
            PrintInterfaceDescription(managerClass, @selector(serviceManagerClientInterface), "serviceManagerClientInterface");
            PrintInterfaceDescription(managerClass, @selector(serviceManagerInterface), "serviceManagerInterface");
            PrintInterfaceDescription(managerClass, @selector(unlockInterface), "unlockInterface");
            return 0;
        }

        if ([command isEqualToString:@"proxy"]) {
            if (argc < 3 || argc > 4) {
                Usage(argv[0]);
            }
            NSString *identifier = [NSString stringWithUTF8String:argv[2]];
            NSTimeInterval seconds = argc >= 4 ? strtod(argv[3], NULL) : 6.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }

            id manager = nil;
            if ([managerClass respondsToSelector:@selector(sharedManager)]) {
                typedef id (*SharedFn)(id, SEL);
                SharedFn fn = (SharedFn)[managerClass methodForSelector:@selector(sharedManager)];
                manager = fn ? fn(managerClass, @selector(sharedManager)) : nil;
            } else {
                manager = [[managerClass alloc] init];
            }
            if (!manager) {
                fprintf(stderr, "failed to create shared manager\n");
                return 1;
            }

            ProbeClient *client = [ProbeClient new];
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            SEL selector = @selector(serviceManagerProxyForIdentifier:client:withCompletionHandler:);
            if (![manager respondsToSelector:selector]) {
                fprintf(stderr, "service manager proxy selector missing\n");
                return 1;
            }
            typedef void (*Fn)(id, SEL, id, id, id);
            Fn fn = (Fn)[manager methodForSelector:selector];
            printf("identifier=%s seconds=%.1f\n", identifier.UTF8String, seconds);
            fn(manager, selector, identifier, client, ^(id proxy, NSError *error) {
                printf("completion.proxy.class=%s\n", proxy ? class_getName([proxy class]) : "nil");
                printf("completion.proxy.value=%s\n", SafeString(proxy).UTF8String);
                printf("completion.error=%s\n", SafeString(error).UTF8String);
                if (proxy) {
                    PrintMethodList([proxy class], "proxy");
                }
                dispatch_semaphore_signal(sem);
            });
            if (!WaitForSemaphore(sem, seconds)) {
                puts("proxy.timeout=true");
            }
            printf("client.event_count=%lu\n", (unsigned long)client.eventCount);
            return 0;
        }

        if ([command isEqualToString:@"message"]) {
            if (argc != 3) {
                Usage(argv[0]);
            }
            NSString *serviceName = [NSString stringWithUTF8String:argv[2]];
            Class serviceClass = NSClassFromString(@"SFCompanionService");
            if (!serviceClass) {
                fprintf(stderr, "SFCompanionService not found\n");
                return 1;
            }
            id service = [[serviceClass alloc] initWithServiceName:serviceName];
            printf("service.class=%s\n", service ? class_getName([service class]) : "nil");
            printf("service.value=%s\n", SafeString(service).UTF8String);
            if ([service respondsToSelector:@selector(messageData)]) {
                typedef id (*GetterFn)(id, SEL);
                GetterFn fn = (GetterFn)[service methodForSelector:@selector(messageData)];
                id messageData = fn(service, @selector(messageData));
                printf("messageData.class=%s\n", messageData ? class_getName([messageData class]) : "nil");
                printf("messageData.value=%s\n", SafeString(messageData).UTF8String);
                if ([messageData isKindOfClass:[NSData class]]) {
                    printf("messageData.length=%lu\n", (unsigned long)[messageData length]);
                    printf("messageData.hex=%s\n", [[messageData description] UTF8String]);
                }
                id decoded = DecodedServiceMessage(service);
                PrintDecodedValue(decoded, "messageDecoded");
            } else {
                puts("messageData.available=false");
            }
            return 0;
        }

        if ([command isEqualToString:@"message-full"]) {
            if (argc != 4) {
                Usage(argv[0]);
            }
            NSString *identifier = [NSString stringWithUTF8String:argv[2]];
            NSString *serviceName = [NSString stringWithUTF8String:argv[3]];
            Class serviceClass = NSClassFromString(@"SFCompanionService");
            if (!serviceClass) {
                fprintf(stderr, "SFCompanionService not found\n");
                return 1;
            }
            id service = [[serviceClass alloc] initWithServiceName:serviceName];
            ConfigureService(service, identifier, serviceName, YES);
            printf("service.class=%s\n", service ? class_getName([service class]) : "nil");
            printf("service.value=%s\n", SafeString(service).UTF8String);
            id decoded = DecodedServiceMessage(service);
            PrintDecodedValue(decoded, "messageFullDecoded");
            PrintBinaryPlistBase64(decoded, "messageFullDecoded");
            return 0;
        }

        if ([command isEqualToString:@"connect-b64"]) {
            if (argc < 3 || argc > 4) {
                Usage(argv[0]);
            }
            NSString *encoded = [NSString stringWithUTF8String:argv[2]];
            NSTimeInterval seconds = argc >= 4 ? strtod(argv[3], NULL) : 6.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }

            NSData *data = [[NSData alloc] initWithBase64EncodedString:encoded options:0];
            if (!data) {
                fprintf(stderr, "invalid base64 plist\n");
                return 1;
            }
            NSError *decodeError = nil;
            id message = [NSPropertyListSerialization propertyListWithData:data
                                                                    options:NSPropertyListImmutable
                                                                     format:nil
                                                                      error:&decodeError];
            if (!message) {
                fprintf(stderr, "plist decode failed: %s\n", SafeString(decodeError).UTF8String);
                return 1;
            }
            PrintDecodedValue(message, "connect.message");

            id manager = nil;
            if ([managerClass respondsToSelector:@selector(sharedManager)]) {
                typedef id (*SharedFn)(id, SEL);
                SharedFn fn = (SharedFn)[managerClass methodForSelector:@selector(sharedManager)];
                manager = fn ? fn(managerClass, @selector(sharedManager)) : nil;
            } else {
                manager = [[managerClass alloc] init];
            }
            if (!manager) {
                fprintf(stderr, "failed to create shared manager\n");
                return 1;
            }

            dispatch_semaphore_t streamSem = dispatch_semaphore_create(0);
            SEL streamsSelector = @selector(streamsForMessage:withCompletionHandler:);
            if (![manager respondsToSelector:streamsSelector]) {
                fprintf(stderr, "streamsForMessage selector missing\n");
                return 1;
            }
            typedef void (*StreamsFn)(id, SEL, id, id);
            StreamsFn streamsFn = (StreamsFn)[manager methodForSelector:streamsSelector];
            puts("connect.streamsForMessage.calling=true");
            streamsFn(manager, streamsSelector, message, ^(NSFileHandle *fileHandle, NSError *error) {
                printf("connect.stream.fileHandle.class=%s\n", fileHandle ? class_getName([fileHandle class]) : "nil");
                printf("connect.stream.fileHandle.value=%s\n", SafeString(fileHandle).UTF8String);
                printf("connect.stream.error=%s\n", SafeString(error).UTF8String);
                const char *relay = getenv("UC_STREAM_RELAY");
                if (relay && relay[0]) {
                    StartRelay(fileHandle, relay, "connect.stream");
                } else {
                    WriteCStringToFileHandle(fileHandle, getenv("UC_STREAM_WRITE"), "connect.stream");
                    PollReadFileHandle(fileHandle, 2000, "connect.stream");
                }
                dispatch_semaphore_signal(streamSem);
            });
            if (!WaitForSemaphore(streamSem, seconds)) {
                puts("connect.stream.timeout=true");
            }
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
            return 0;
        }

        if ([command isEqualToString:@"enable"] ||
            [command isEqualToString:@"enable-full"] ||
            [command isEqualToString:@"enable-activity"] ||
            [command isEqualToString:@"enable-full-activity"]) {
            if (argc < 4 || argc > 5) {
                Usage(argv[0]);
            }
            NSString *identifier = [NSString stringWithUTF8String:argv[2]];
            NSString *serviceName = [NSString stringWithUTF8String:argv[3]];
            BOOL fillPeerFields = [command isEqualToString:@"enable-full"] || [command isEqualToString:@"enable-full-activity"];
            BOOL startActivity = [command isEqualToString:@"enable-activity"] || [command isEqualToString:@"enable-full-activity"];
            NSTimeInterval seconds = argc >= 5 ? strtod(argv[4], NULL) : 6.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }

            id manager = nil;
            if ([managerClass respondsToSelector:@selector(sharedManager)]) {
                typedef id (*SharedFn)(id, SEL);
                SharedFn fn = (SharedFn)[managerClass methodForSelector:@selector(sharedManager)];
                manager = fn ? fn(managerClass, @selector(sharedManager)) : nil;
            } else {
                manager = [[managerClass alloc] init];
            }
            if (!manager) {
                fprintf(stderr, "failed to create shared manager\n");
                return 1;
            }

            Class serviceClass = NSClassFromString(@"SFCompanionService");
            if (!serviceClass) {
                fprintf(stderr, "SFCompanionService not found\n");
                return 1;
            }
            id service = [[serviceClass alloc] initWithServiceName:serviceName];
            ConfigureService(service, identifier, serviceName, fillPeerFields);

            ProbeClient *client = [ProbeClient new];
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            __block BOOL didEnable = NO;
            __block id retainedProxy = nil;
            SEL proxySelector = @selector(serviceManagerProxyForIdentifier:client:withCompletionHandler:);
            SEL enableSelector = @selector(enableService:);
            if (![manager respondsToSelector:proxySelector]) {
                fprintf(stderr, "service manager proxy selector missing\n");
                return 1;
            }
            typedef void (*ProxyFn)(id, SEL, id, id, id);
            ProxyFn proxyFn = (ProxyFn)[manager methodForSelector:proxySelector];
            printf("identifier=%s service=%s seconds=%.1f\n",
                   identifier.UTF8String,
                   serviceName.UTF8String,
                   seconds);
            printf("service.class=%s\n", service ? class_getName([service class]) : "nil");
            printf("service.value=%s\n", SafeString(service).UTF8String);
            if (fillPeerFields) {
                id decoded = DecodedServiceMessage(service);
                PrintDecodedValue(decoded, "enableFull.message");
                PrintBinaryPlistBase64(decoded, "enableFull.message");
            }
            proxyFn(manager, proxySelector, identifier, client, ^(id proxy, NSError *error) {
                retainedProxy = proxy;
                printf("completion.proxy.class=%s\n", proxy ? class_getName([proxy class]) : "nil");
                printf("completion.proxy.value=%s\n", SafeString(proxy).UTF8String);
                printf("completion.error=%s\n", SafeString(error).UTF8String);
                if (proxy && [proxy respondsToSelector:enableSelector]) {
                    typedef void (*EnableFn)(id, SEL, id);
                    EnableFn enableFn = (EnableFn)[proxy methodForSelector:enableSelector];
                    printf("proxy.enableService.calling=true\n");
                    enableFn(proxy, enableSelector, service);
                    printf("proxy.enableService.called=true\n");
                    didEnable = YES;
                } else {
                    printf("proxy.enableService.available=false\n");
                }
                dispatch_semaphore_signal(sem);
            });
            if (!WaitForSemaphore(sem, seconds)) {
                puts("enable.timeout=true");
            }
            if (didEnable) {
                NSUserActivity *activity = nil;
                if (startActivity) {
                    activity = StartUserActivity(serviceName, identifier);
                }
                printf("enable.hold_open.seconds=%.1f\n", seconds);
                [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
                if (activity) {
                    [activity invalidate];
                    puts("activity.invalidated=true");
                }
            }
            (void)retainedProxy;
            printf("client.event_count=%lu\n", (unsigned long)client.eventCount);
            return 0;
        }

        if ([command isEqualToString:@"loopback"]) {
            if (argc < 4 || argc > 5) {
                Usage(argv[0]);
            }
            NSString *identifier = [NSString stringWithUTF8String:argv[2]];
            NSString *serviceName = [NSString stringWithUTF8String:argv[3]];
            NSTimeInterval seconds = argc >= 5 ? strtod(argv[4], NULL) : 6.0;
            if (seconds < 0.1) {
                seconds = 0.1;
            }

            id manager = nil;
            if ([managerClass respondsToSelector:@selector(sharedManager)]) {
                typedef id (*SharedFn)(id, SEL);
                SharedFn fn = (SharedFn)[managerClass methodForSelector:@selector(sharedManager)];
                manager = fn ? fn(managerClass, @selector(sharedManager)) : nil;
            } else {
                manager = [[managerClass alloc] init];
            }
            if (!manager) {
                fprintf(stderr, "failed to create shared manager\n");
                return 1;
            }

            Class serviceClass = NSClassFromString(@"SFCompanionService");
            if (!serviceClass) {
                fprintf(stderr, "SFCompanionService not found\n");
                return 1;
            }
            id service = [[serviceClass alloc] initWithServiceName:serviceName];
            ConfigureService(service, identifier, serviceName, YES);

            ProbeClient *client = [ProbeClient new];
            dispatch_semaphore_t proxySem = dispatch_semaphore_create(0);
            dispatch_semaphore_t streamSem = dispatch_semaphore_create(0);
            __block BOOL didEnable = NO;
            __block id retainedProxy = nil;

            SEL proxySelector = @selector(serviceManagerProxyForIdentifier:client:withCompletionHandler:);
            typedef void (*ProxyFn)(id, SEL, id, id, id);
            ProxyFn proxyFn = (ProxyFn)[manager methodForSelector:proxySelector];
            printf("loopback.identifier=%s service=%s seconds=%.1f\n",
                   identifier.UTF8String,
                   serviceName.UTF8String,
                   seconds);
            proxyFn(manager, proxySelector, identifier, client, ^(id proxy, NSError *error) {
                retainedProxy = proxy;
                printf("loopback.proxy.class=%s\n", proxy ? class_getName([proxy class]) : "nil");
                printf("loopback.proxy.value=%s\n", SafeString(proxy).UTF8String);
                printf("loopback.proxy.error=%s\n", SafeString(error).UTF8String);
                SEL enableSelector = @selector(enableService:);
                if (proxy && [proxy respondsToSelector:enableSelector]) {
                    typedef void (*EnableFn)(id, SEL, id);
                    EnableFn enableFn = (EnableFn)[proxy methodForSelector:enableSelector];
                    enableFn(proxy, enableSelector, service);
                    didEnable = YES;
                    puts("loopback.enableService.called=true");
                }
                dispatch_semaphore_signal(proxySem);
            });
            if (!WaitForSemaphore(proxySem, seconds)) {
                puts("loopback.proxy.timeout=true");
            }

            id message = DecodedServiceMessage(service);
            printf("loopback.message.class=%s\n", message ? class_getName([message class]) : "nil");
            printf("loopback.message.value=%s\n", SafeString(message).UTF8String);
            SEL streamsSelector = @selector(streamsForMessage:withCompletionHandler:);
            if (didEnable && message && [manager respondsToSelector:streamsSelector]) {
                typedef void (*StreamsFn)(id, SEL, id, id);
                StreamsFn streamsFn = (StreamsFn)[manager methodForSelector:streamsSelector];
                puts("loopback.streamsForMessage.calling=true");
                streamsFn(manager, streamsSelector, message, ^(NSFileHandle *fileHandle, NSError *error) {
                    printf("loopback.stream.fileHandle.class=%s\n", fileHandle ? class_getName([fileHandle class]) : "nil");
                    printf("loopback.stream.fileHandle.value=%s\n", SafeString(fileHandle).UTF8String);
                    printf("loopback.stream.error=%s\n", SafeString(error).UTF8String);
                    const char *relay = getenv("UC_STREAM_RELAY");
                    if (relay && relay[0]) {
                        StartRelay(fileHandle, relay, "loopback.stream");
                    } else {
                        WriteCStringToFileHandle(fileHandle, getenv("UC_STREAM_WRITE"), "loopback.stream");
                        PollReadFileHandle(fileHandle, 2000, "loopback.stream");
                    }
                    dispatch_semaphore_signal(streamSem);
                });
                if (!WaitForSemaphore(streamSem, seconds)) {
                    puts("loopback.stream.timeout=true");
                }
            } else {
                puts("loopback.streamsForMessage.skipped=true");
            }
            (void)retainedProxy;
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
            printf("client.event_count=%lu\n", (unsigned long)client.eventCount);
            return 0;
        }

        Usage(argv[0]);
    }
}
