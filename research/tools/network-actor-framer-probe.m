#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <Security/Security.h>
#import <Security/SecProtocolOptions.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <objc/message.h>

static const char *kActorFramerIdentifier = "com.apple.network.MessageActorSystem";
static const char *kActorTypeKey = "NWActorSystemType";
static const char *kActorOptionsKey = "NWActorSystemOptions";

extern nw_protocol_definition_t nw_protocol_copy_definition_for_identifier(const char *identifier) __attribute__((weak_import));
extern nw_endpoint_t nw_endpoint_create_application_service(const char *application_service_name) __attribute__((weak_import));
extern nw_parameters_t nw_parameters_create_application_service_quic(void) __attribute__((weak_import));
extern nw_parameters_t nw_parameters_create_application_service_quic_using_identity(sec_identity_t identity) __attribute__((weak_import));

static void AppendVarint(NSMutableData *data, uint64_t value) {
    do {
        uint8_t byte = value & 0x7f;
        value >>= 7;
        if (value != 0) {
            byte |= 0x80;
        }
        [data appendBytes:&byte length:1];
    } while (value != 0);
}

static void AppendProtobufBytesField(NSMutableData *data, uint32_t fieldNumber, NSData *value) {
    AppendVarint(data, ((uint64_t)fieldNumber << 3) | 2);
    AppendVarint(data, value.length);
    [data appendData:value];
}

static void AppendProtobufStringField(NSMutableData *data, uint32_t fieldNumber, NSString *value) {
    NSData *bytes = [value dataUsingEncoding:NSUTF8StringEncoding];
    AppendProtobufBytesField(data, fieldNumber, bytes ?: [NSData data]);
}

static void AppendProtobufVarintField(NSMutableData *data, uint32_t fieldNumber, uint64_t value) {
    AppendVarint(data, ((uint64_t)fieldNumber << 3) | 0);
    AppendVarint(data, value);
}

static NSData *ActorIDProtobuf(NSString *actorName, NSString *identifier) {
    NSMutableData *data = [NSMutableData data];
    AppendProtobufStringField(data, 1, actorName);
    AppendProtobufStringField(data, 2, identifier);
    return data;
}

static NSData *RemoteCallProtobuf(NSString *callID,
                                  NSString *actorName,
                                  NSString *actorIdentifier,
                                  NSString *target,
                                  uint64_t options,
                                  NSArray<NSData *> *arguments) {
    NSMutableData *data = [NSMutableData data];
    AppendProtobufStringField(data, 1, callID);
    AppendProtobufBytesField(data, 2, ActorIDProtobuf(actorName, actorIdentifier));
    AppendProtobufStringField(data, 3, target);
    for (NSData *argument in arguments) {
        AppendProtobufBytesField(data, 5, argument);
    }
    AppendProtobufVarintField(data, 6, options);
    return data;
}

static NSData *HexDataFromString(NSString *hex) {
    NSMutableData *data = [NSMutableData data];
    NSUInteger length = hex.length;
    if ((length % 2) != 0) {
        return nil;
    }
    for (NSUInteger i = 0; i + 1 < length; i += 2) {
        NSString *pair = [hex substringWithRange:NSMakeRange(i, 2)];
        unsigned value = 0;
        NSScanner *scanner = [NSScanner scannerWithString:pair];
        if (![scanner scanHexInt:&value]) {
            return nil;
        }
        uint8_t byte = (uint8_t)value;
        [data appendBytes:&byte length:1];
    }
    return data;
}

static NSString *HexStringFromData(NSData *data) {
    const uint8_t *bytes = data.bytes;
    if (!bytes) {
        return @"";
    }
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

static NSString *EnvironmentString(const char *name) {
    const char *value = getenv(name);
    if (!value || value[0] == '\0') {
        return nil;
    }
    return [NSString stringWithUTF8String:value];
}

static void ApplyAttributedBundleIdentifier(nw_parameters_t parameters) {
    NSString *bundleID = EnvironmentString("MACOLINUX_ATTRIBUTED_BUNDLE_ID");
    if (bundleID.length == 0) {
        return;
    }

    typedef void (*SetAttributedBundleIdentifierFn)(nw_parameters_t, const char *);
    typedef const char *(*GetAttributedBundleIdentifierFn)(nw_parameters_t);
    SetAttributedBundleIdentifierFn setAttributedBundleIdentifier =
        (SetAttributedBundleIdentifierFn)dlsym(RTLD_DEFAULT, "nw_parameters_set_attributed_bundle_identifier");
    GetAttributedBundleIdentifierFn getAttributedBundleIdentifier =
        (GetAttributedBundleIdentifierFn)dlsym(RTLD_DEFAULT, "nw_parameters_get_attributed_bundle_identifier");
    if (!setAttributedBundleIdentifier) {
        puts("nw_parameters_set_attributed_bundle_identifier unavailable");
        return;
    }

    setAttributedBundleIdentifier(parameters, bundleID.UTF8String);
    const char *effectiveBundleID = getAttributedBundleIdentifier ? getAttributedBundleIdentifier(parameters) : NULL;
    printf("parameters attributed_bundle_id=%s\n",
           effectiveBundleID ? effectiveBundleID : bundleID.UTF8String);
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
        NSData *data = HexDataFromString([argument substringFromIndex:4]);
        if (!data) {
            fprintf(stderr, "invalid hex data: %s\n", argument.UTF8String);
        }
        return data;
    }
    return [argument dataUsingEncoding:NSUTF8StringEncoding];
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
    return dispatch_data_create(buffer,
                                data.length,
                                dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0),
                                DISPATCH_DATA_DESTRUCTOR_FREE);
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
    printf("%s: dispatch_len=%zu hex=%s\n", label, size, HexStringFromData(bytes).UTF8String);
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

static sec_identity_t CreateClientPAKEIdentity(NSString *clientIdentity, NSString *serverIdentity) {
    NSString *passwordArg = EnvironmentString("MACOLINUX_PAKE_PASSWORD");
    if (passwordArg.length == 0) {
        puts("pake challenge response disabled: MACOLINUX_PAKE_PASSWORD is unset");
        return NULL;
    }

    NSString *contextArg = EnvironmentString("MACOLINUX_PAKE_CONTEXT");
    if (contextArg.length == 0) {
        contextArg = @"hex:00";
    }
    NSString *clientOverride = EnvironmentString("MACOLINUX_PAKE_CLIENT_ID");
    NSString *serverOverride = EnvironmentString("MACOLINUX_PAKE_SERVER_ID");
    NSString *effectiveClient = clientOverride.length > 0 ? clientOverride : clientIdentity;
    NSString *effectiveServer = serverOverride.length > 0 ? serverOverride : serverIdentity;

    if (effectiveClient.length == 0 || effectiveServer.length == 0) {
        printf("pake challenge response skipped: client=%s server=%s\n",
               effectiveClient.UTF8String ?: "",
               effectiveServer.UTF8String ?: "");
        return NULL;
    }

    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    printf("pake Security handle=%p\n", security);

    typedef id (*CreateClientFn)(dispatch_data_t, dispatch_data_t, dispatch_data_t, dispatch_data_t, int);
    CreateClientFn createClient = (CreateClientFn)dlsym(RTLD_DEFAULT, "sec_identity_create_client_SPAKE2PLUSV1_identity");
    if (!createClient) {
        puts("sec_identity_create_client_SPAKE2PLUSV1_identity unavailable");
        return NULL;
    }

    NSData *contextBytes = DataFromProbeArgument(contextArg);
    NSData *clientBytes = [effectiveClient dataUsingEncoding:NSUTF8StringEncoding];
    NSData *serverBytes = [effectiveServer dataUsingEncoding:NSUTF8StringEncoding];
    NSData *passwordBytes = DataFromProbeArgument(passwordArg);

    dispatch_data_t contextData = DispatchDataFromNSData(contextBytes);
    dispatch_data_t clientData = DispatchDataFromNSData(clientBytes);
    dispatch_data_t serverData = DispatchDataFromNSData(serverBytes);
    dispatch_data_t passwordData = DispatchDataFromNSData(passwordBytes);

    PrintDispatchDataObject(contextData, "pake.response.context");
    PrintDispatchDataObject(clientData, "pake.response.client_identity");
    PrintDispatchDataObject(serverData, "pake.response.server_identity");
    PrintDispatchDataObject(passwordData, "pake.response.password");

    id identity = createClient(contextData, clientData, serverData, passwordData, 0);
    printf("pake response identity=%s\n", identity ? [[identity description] UTF8String] : "nil");
    if (identity) {
        PrintSPAKEIdentityFields(identity);
    }
    return identity ? (sec_identity_t)identity : NULL;
}

static NSData *JsonStringData(NSString *value) {
    NSMutableString *json = [NSMutableString stringWithString:@"\""];
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar ch = [value characterAtIndex:i];
        switch (ch) {
            case '\\':
                [json appendString:@"\\\\"];
                break;
            case '"':
                [json appendString:@"\\\""];
                break;
            case '\n':
                [json appendString:@"\\n"];
                break;
            case '\r':
                [json appendString:@"\\r"];
                break;
            case '\t':
                [json appendString:@"\\t"];
                break;
            default:
                if (ch < 0x20) {
                    [json appendFormat:@"\\u%04x", ch];
                } else {
                    [json appendFormat:@"%C", ch];
                }
                break;
        }
    }
    [json appendString:@"\""];
    return [json dataUsingEncoding:NSUTF8StringEncoding];
}

static NSData *RemoteCallArgumentFromPart(NSString *part) {
    if ([part isEqualToString:@"arg-empty"]) {
        return [NSData data];
    }
    if ([part hasPrefix:@"arg-hex:"]) {
        return HexDataFromString([part substringFromIndex:[@"arg-hex:" length]]);
    }
    if ([part hasPrefix:@"arg-b64:"]) {
        return [[NSData alloc] initWithBase64EncodedString:[part substringFromIndex:[@"arg-b64:" length]] options:0];
    }
    if ([part hasPrefix:@"arg-text:"]) {
        return [[part substringFromIndex:[@"arg-text:" length]] dataUsingEncoding:NSUTF8StringEncoding];
    }
    if ([part hasPrefix:@"arg-json-string:"]) {
        return JsonStringData([part substringFromIndex:[@"arg-json-string:" length]]);
    }
    if ([part hasPrefix:@"arg-json-data-b64:"]) {
        return JsonStringData([part substringFromIndex:[@"arg-json-data-b64:" length]]);
    }
    if ([part hasPrefix:@"arg-json-data-hex:"]) {
        NSData *data = HexDataFromString([part substringFromIndex:[@"arg-json-data-hex:" length]]);
        if (!data) {
            return nil;
        }
        return JsonStringData([data base64EncodedStringWithOptions:0]);
    }
    if ([part isEqualToString:@"arg-json-bool:true"]) {
        return [@"true" dataUsingEncoding:NSUTF8StringEncoding];
    }
    if ([part isEqualToString:@"arg-json-bool:false"]) {
        return [@"false" dataUsingEncoding:NSUTF8StringEncoding];
    }
    return nil;
}

static NSData *RemoteCallProtobufFromBody(NSString *body) {
    NSArray<NSString *> *parts = [body componentsSeparatedByString:@"|"];
    if (parts.count < 4) {
        return nil;
    }
    uint64_t options = 0;
    if (parts.count >= 5) {
        options = strtoull(parts[4].UTF8String, NULL, 0);
    }

    NSMutableArray<NSData *> *arguments = [NSMutableArray array];
    for (NSUInteger i = 5; i < parts.count; i++) {
        NSData *argument = RemoteCallArgumentFromPart(parts[i]);
        if (!argument) {
            return nil;
        }
        [arguments addObject:argument];
    }
    return RemoteCallProtobuf(parts[0], parts[1], parts[2], parts[3], options, arguments);
}

static NSData *RemoteCallProtobufFromMode(NSString *mode) {
    return RemoteCallProtobufFromBody([mode substringFromIndex:[@"remote-call:" length]]);
}

static NSArray<NSString *> *RemoteCallSequenceBodies(NSString *mode) {
    NSString *body = [mode substringFromIndex:[@"remote-call-sequence:" length]];
    NSArray<NSString *> *parts = [body componentsSeparatedByString:@";;;"];
    return parts.count == 2 ? parts : nil;
}

static NSData *RemoteCallSequenceFirstPayload(NSString *mode) {
    NSArray<NSString *> *bodies = RemoteCallSequenceBodies(mode);
    return bodies ? RemoteCallProtobufFromBody(bodies[0]) : nil;
}

static NSData *RemoteCallSequenceSecondPayload(NSString *mode) {
    NSArray<NSString *> *bodies = RemoteCallSequenceBodies(mode);
    return bodies ? RemoteCallProtobufFromBody(bodies[1]) : nil;
}

static NSString *PairVerifyStartWithSessionTarget(void) {
    return @"$s8rapportd25RPPairingDistributedActorC28startPairVerifyWithSessionID22createEncryptionStream10Foundation4UUIDVSb_tYaKFTE";
}

static NSString *PairVerifyProcessWithSessionTarget(void) {
    return @"$s8rapportd25RPPairingDistributedActorC34processPairVerifyDataWithSessionID_07sessionK010Foundation0H0VSgAH_AF4UUIDVtYaKFTE";
}

static NSArray<NSString *> *PairVerifySequenceParts(NSString *mode) {
    NSString *body = [mode substringFromIndex:[@"pairverify-sequence:" length]];
    NSArray<NSString *> *parts = [body componentsSeparatedByString:@"|"];
    return parts.count == 6 ? parts : nil;
}

static NSData *PairVerifySequenceStartPayload(NSString *mode) {
    NSArray<NSString *> *parts = PairVerifySequenceParts(mode);
    if (!parts) {
        return nil;
    }
    NSString *boolValue = [parts[4] isEqualToString:@"true"] ? @"true" : @"false";
    return RemoteCallProtobuf(parts[0],
                              parts[2],
                              parts[3],
                              PairVerifyStartWithSessionTarget(),
                              0,
                              @[ [boolValue dataUsingEncoding:NSUTF8StringEncoding] ]);
}

static NSData *PairVerifySequenceProcessPayload(NSString *mode, NSString *sessionID) {
    NSArray<NSString *> *parts = PairVerifySequenceParts(mode);
    if (!parts) {
        return nil;
    }
    NSData *m1 = HexDataFromString(parts[5]);
    if (!m1) {
        return nil;
    }
    NSData *m1JSON = JsonStringData([m1 base64EncodedStringWithOptions:0]);
    NSData *sessionJSON = JsonStringData(sessionID);
    return RemoteCallProtobuf(parts[1],
                              parts[2],
                              parts[3],
                              PairVerifyProcessWithSessionTarget(),
                              0,
                              @[ m1JSON, sessionJSON ]);
}

static BOOL IsUUIDCharAt(const uint8_t *bytes, NSUInteger offset) {
    uint8_t c = bytes[offset];
    if (offset == 8 || offset == 13 || offset == 18 || offset == 23) {
        return c == '-';
    }
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static NSString *ExtractJSONUUID(NSData *data) {
    const uint8_t *bytes = data.bytes;
    if (!bytes || data.length < 38) {
        return nil;
    }
    for (NSUInteger i = 0; i + 37 < data.length; i++) {
        if (bytes[i] != '"' || bytes[i + 37] != '"') {
            continue;
        }
        BOOL matches = YES;
        for (NSUInteger j = 0; j < 36; j++) {
            if (!IsUUIDCharAt(bytes + i + 1, j)) {
                matches = NO;
                break;
            }
        }
        if (matches) {
            return [[NSString alloc] initWithBytes:bytes + i + 1 length:36 encoding:NSUTF8StringEncoding];
        }
    }
    return nil;
}

static NSData *ExtractJSONBase64Data(NSData *data) {
    const uint8_t *bytes = data.bytes;
    if (!bytes || data.length < 4) {
        return nil;
    }
    for (NSUInteger i = 0; i < data.length; i++) {
        if (bytes[i] != '"') {
            continue;
        }
        NSUInteger start = i + 1;
        NSUInteger end = start;
        BOOL escaped = NO;
        while (end < data.length) {
            uint8_t c = bytes[end];
            if (escaped) {
                escaped = NO;
            } else if (c == '\\') {
                escaped = YES;
            } else if (c == '"') {
                break;
            }
            end++;
        }
        if (end >= data.length) {
            break;
        }
        if (end > start) {
            NSString *candidate = [[NSString alloc] initWithBytes:bytes + start
                                                           length:end - start
                                                         encoding:NSUTF8StringEncoding];
            NSData *decoded = [[NSData alloc] initWithBase64EncodedString:candidate ?: @""
                                                                  options:NSDataBase64DecodingIgnoreUnknownCharacters];
            if (decoded.length > 0) {
                return decoded;
            }
        }
        i = end;
    }
    return nil;
}

static NSArray<NSString *> *PairVerifyM3SequenceParts(NSString *mode) {
    NSString *body = [mode substringFromIndex:[@"pairverify-m3-sequence:" length]];
    NSArray<NSString *> *parts = [body componentsSeparatedByString:@"|"];
    return parts.count == 8 ? parts : nil;
}

static NSDictionary<NSString *, NSString *> *KeyValueLines(NSString *text) {
    NSMutableDictionary<NSString *, NSString *> *values = [NSMutableDictionary dictionary];
    NSArray<NSString *> *lines = [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString *line in lines) {
        NSRange separator = [line rangeOfString:@"="];
        if (separator.location == NSNotFound || separator.location == 0) {
            continue;
        }
        NSString *key = [line substringToIndex:separator.location];
        NSString *value = [line substringFromIndex:separator.location + 1];
        values[key] = value;
    }
    return values;
}

static NSDictionary<NSString *, NSString *> *RunPairVerifyHelper(NSString *helperPath,
                                                                  NSArray<NSString *> *arguments) {
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:helperPath];
    task.arguments = arguments;

    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;

    NSError *launchError = nil;
    if (![task launchAndReturnError:&launchError]) {
        fprintf(stderr, "pairverify-m3-sequence: failed to launch helper %s: %s\n",
                helperPath.UTF8String, launchError.localizedDescription.UTF8String);
        return nil;
    }
    [task waitUntilExit];

    NSData *outputData = [[pipe fileHandleForReading] readDataToEndOfFile];
    NSString *output = [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding] ?: @"";
    if (task.terminationStatus != 0) {
        fprintf(stderr, "pairverify-m3-sequence: helper failed status=%d output=%s\n",
                task.terminationStatus, output.UTF8String);
        return nil;
    }
    return KeyValueLines(output);
}

static NSMutableDictionary<NSString *, NSString *> *PairVerifyM3SequenceInitialState(NSString *mode) {
    NSArray<NSString *> *parts = PairVerifyM3SequenceParts(mode);
    if (!parts) {
        return nil;
    }
    NSDictionary<NSString *, NSString *> *m1 = RunPairVerifyHelper(parts[6], @[ @"m1" ]);
    NSString *secretKey = m1[@"secret_key_hex"];
    NSString *m1Hex = m1[@"m1_hex"];
    if (secretKey.length == 0 || m1Hex.length == 0) {
        puts("pairverify-m3-sequence: helper did not return secret_key_hex and m1_hex");
        return nil;
    }
    NSMutableDictionary<NSString *, NSString *> *state = [NSMutableDictionary dictionary];
    state[@"secret_key_hex"] = secretKey;
    state[@"m1_hex"] = m1Hex;
    state[@"helper_path"] = parts[6];
    state[@"identity_path"] = parts[7];
    return state;
}

static NSData *PairVerifyM3SequenceStartPayload(NSString *mode,
                                                NSMutableDictionary<NSString *, NSString *> **stateOut) {
    NSArray<NSString *> *parts = PairVerifyM3SequenceParts(mode);
    if (!parts) {
        return nil;
    }
    NSMutableDictionary<NSString *, NSString *> *state = PairVerifyM3SequenceInitialState(mode);
    if (!state) {
        return nil;
    }
    if (stateOut) {
        *stateOut = state;
    }
    NSString *boolValue = [parts[5] isEqualToString:@"true"] ? @"true" : @"false";
    return RemoteCallProtobuf(parts[0],
                              parts[3],
                              parts[4],
                              PairVerifyStartWithSessionTarget(),
                              0,
                              @[ [boolValue dataUsingEncoding:NSUTF8StringEncoding] ]);
}

static NSData *PairVerifyM3SequenceProcessPayload(NSString *mode,
                                                  NSString *callID,
                                                  NSString *sessionID,
                                                  NSData *pairVerifyData) {
    NSArray<NSString *> *parts = PairVerifyM3SequenceParts(mode);
    if (!parts) {
        return nil;
    }
    NSData *pairVerifyJSON = JsonStringData([pairVerifyData base64EncodedStringWithOptions:0]);
    NSData *sessionJSON = JsonStringData(sessionID);
    return RemoteCallProtobuf(callID,
                              parts[3],
                              parts[4],
                              PairVerifyProcessWithSessionTarget(),
                              0,
                              @[ pairVerifyJSON, sessionJSON ]);
}

static NSData *PairVerifyM3SequenceM1Payload(NSString *mode,
                                             NSString *sessionID,
                                             NSDictionary<NSString *, NSString *> *state) {
    NSData *m1 = HexDataFromString(state[@"m1_hex"]);
    if (!m1) {
        return nil;
    }
    NSArray<NSString *> *parts = PairVerifyM3SequenceParts(mode);
    if (!parts) {
        return nil;
    }
    return PairVerifyM3SequenceProcessPayload(mode, parts[1], sessionID, m1);
}

static NSData *PairVerifyM3SequenceM3Payload(NSString *mode,
                                             NSString *sessionID,
                                             NSData *m2,
                                             NSMutableDictionary<NSString *, NSString *> *state) {
    NSArray<NSString *> *parts = PairVerifyM3SequenceParts(mode);
    if (!parts) {
        return nil;
    }
    NSDictionary<NSString *, NSString *> *m3 = RunPairVerifyHelper(state[@"helper_path"],
                                                                   @[ @"m3",
                                                                      @"--secret-key-hex", state[@"secret_key_hex"],
                                                                      @"--m2-hex", HexStringFromData(m2),
                                                                      @"--identity", state[@"identity_path"] ]);
    NSString *m3Hex = m3[@"m3_hex"];
    NSString *sharedSecretHex = m3[@"shared_secret_hex"];
    NSString *pairVerifyKeyHex = m3[@"pairverify_encryption_key_hex"];
    if (sharedSecretHex.length > 0) {
        state[@"shared_secret_hex"] = sharedSecretHex;
        printf("pairverify-m3-sequence: eopack_decrypt_psk_hex=%s\n", sharedSecretHex.UTF8String);
    }
    if (pairVerifyKeyHex.length > 0) {
        state[@"pairverify_encryption_key_hex"] = pairVerifyKeyHex;
        printf("pairverify-m3-sequence: pairverify_encryption_key_hex=%s\n", pairVerifyKeyHex.UTF8String);
    }
    NSData *m3Data = HexDataFromString(m3Hex ?: @"");
    if (!m3Data) {
        return nil;
    }
    return PairVerifyM3SequenceProcessPayload(mode, parts[2], sessionID, m3Data);
}

static const char *ConnectionStateName(nw_connection_state_t state) {
    switch (state) {
        case nw_connection_state_invalid: return "invalid";
        case nw_connection_state_waiting: return "waiting";
        case nw_connection_state_preparing: return "preparing";
        case nw_connection_state_ready: return "ready";
        case nw_connection_state_failed: return "failed";
        case nw_connection_state_cancelled: return "cancelled";
        default: return "unknown";
    }
}

static const char *BrowserStateName(nw_browser_state_t state) {
    switch (state) {
        case nw_browser_state_invalid: return "invalid";
        case nw_browser_state_ready: return "ready";
        case nw_browser_state_failed: return "failed";
        case nw_browser_state_cancelled: return "cancelled";
        case nw_browser_state_waiting: return "waiting";
        default: return "unknown";
    }
}

static NSString *HexStringFromBytes(const uint8_t *bytes, size_t length) {
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (size_t i = 0; i < length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

static void PrintTXTRecord(NSString *prefix, nw_txt_record_t txtRecord) {
    if (!txtRecord) {
        printf("%s txt=nil\n", prefix.UTF8String);
        return;
    }
    printf("%s txt_keys=%zu txt=%s\n",
           prefix.UTF8String,
           nw_txt_record_get_key_count(txtRecord),
           [[(id)txtRecord description] UTF8String]);
    nw_txt_record_apply(txtRecord, ^bool(const char *key,
                                         const nw_txt_record_find_key_t found,
                                         const uint8_t *value,
                                         const size_t valueLength) {
        NSString *valueText = value && valueLength > 0
            ? [[NSString alloc] initWithBytes:value length:valueLength encoding:NSUTF8StringEncoding]
            : nil;
        NSString *valueHex = value && valueLength > 0
            ? HexStringFromBytes(value, valueLength)
            : @"";
        printf("%s txt[%s] found=%d len=%zu value=%s hex=%s\n",
               prefix.UTF8String,
               key ?: "",
               found,
               valueLength,
               valueText.UTF8String ?: "",
               valueHex.UTF8String);
        return true;
    });
}

static void PrintEndpointSignature(NSString *prefix, nw_endpoint_t endpoint) {
    if (!endpoint) {
        printf("%s signature=nil\n", prefix.UTF8String);
        return;
    }
    size_t signatureLength = 0;
    const uint8_t *signature = nw_endpoint_get_signature(endpoint, &signatureLength);
    if (!signature || signatureLength == 0) {
        printf("%s signature=nil\n", prefix.UTF8String);
        return;
    }
    printf("%s signature_len=%zu signature_hex=%s\n",
           prefix.UTF8String,
           signatureLength,
           HexStringFromBytes(signature, signatureLength).UTF8String);
}

static NSData *PayloadFromMode(NSString *mode) {
    if (!mode || [mode isEqualToString:@"empty"]) {
        return [NSData data];
    }
    if ([mode isEqualToString:@"zero"]) {
        const uint8_t byte = 0;
        return [NSData dataWithBytes:&byte length:1];
    }
    if ([mode isEqualToString:@"rpnw-control"]) {
        const uint8_t bytes[] = {
            0x01, 0x00, 0x00, 0x00,
            0x13, 0x13, 0x13, 0x13,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        };
        return [NSData dataWithBytes:bytes length:sizeof(bytes)];
    }
    if ([mode hasPrefix:@"hex:"]) {
        NSString *hex = [mode substringFromIndex:4];
        return HexDataFromString(hex);
    }
    if ([mode hasPrefix:@"b64:"]) {
        NSString *base64 = [mode substringFromIndex:4];
        return [[NSData alloc] initWithBase64EncodedString:base64 options:0];
    }
    if ([mode hasPrefix:@"file:"]) {
        NSString *path = [mode substringFromIndex:5];
        return [NSData dataWithContentsOfFile:path];
    }
    if ([mode hasPrefix:@"remote-call:"]) {
        return RemoteCallProtobufFromMode(mode);
    }
    if ([mode hasPrefix:@"remote-call-sequence:"]) {
        return RemoteCallSequenceFirstPayload(mode);
    }
    if ([mode hasPrefix:@"pairverify-sequence:"]) {
        return PairVerifySequenceStartPayload(mode);
    }
    if ([mode hasPrefix:@"pairverify-m3-sequence:"]) {
        return PairVerifyM3SequenceStartPayload(mode, NULL);
    }
    if ([mode hasPrefix:@"text:"]) {
        return [[mode substringFromIndex:5] dataUsingEncoding:NSUTF8StringEncoding];
    }
    return [mode dataUsingEncoding:NSUTF8StringEncoding];
}

static uint32_t ActorWireTypeForLogicalType(NSInteger actorType) {
    static const uint32_t typeMap[] = { 0, 5, 6, 7, 8 };
    if (actorType >= 0 && actorType < (NSInteger)(sizeof(typeMap) / sizeof(typeMap[0]))) {
        return typeMap[actorType];
    }
    return (uint32_t)actorType;
}

static int8_t LogicalTypeForActorWireType(uint32_t wireType) {
    if (wireType >= 5 && wireType <= 8) {
        return (int8_t)(wireType - 4);
    }
    return 0;
}

static NSInteger IntegerObjectValue(nw_framer_message_t message, const char *key, NSInteger fallback) {
    id value = nw_framer_message_copy_object_value(message, key);
    if (!value) {
        return fallback;
    }
    NSInteger integerValue = fallback;
    if ([value respondsToSelector:@selector(integerValue)]) {
        integerValue = [value integerValue];
    }
    return integerValue;
}

static nw_protocol_definition_t CreatePassThroughActorDefinition(void) {
    return nw_framer_create_definition(kActorFramerIdentifier,
                                       NW_FRAMER_CREATE_FLAGS_DEFAULT,
                                       ^nw_framer_start_result_t(nw_framer_t framer) {
        nw_framer_set_input_handler(framer, ^size_t(nw_framer_t inputFramer) {
            nw_framer_pass_through_input(inputFramer);
            return 0;
        });
        nw_framer_set_output_handler(framer, ^(nw_framer_t outputFramer,
                                               nw_framer_message_t message,
                                               size_t messageLength,
                                               bool isComplete) {
            (void)message;
            (void)isComplete;
            nw_framer_write_output_no_copy(outputFramer, messageLength);
        });
        return nw_framer_start_result_ready;
    });
}

static nw_protocol_definition_t CreateActorWireDefinition(void) {
    return nw_framer_create_definition(kActorFramerIdentifier,
                                       NW_FRAMER_CREATE_FLAGS_DEFAULT,
                                       ^nw_framer_start_result_t(nw_framer_t framer) {
        nw_framer_set_input_handler(framer, ^size_t(nw_framer_t inputFramer) {
            __block BOOL parsedHeader = NO;
            __block uint32_t wireType = 0;
            __block uint32_t actorOptions = 0;
            __block uint32_t bodyLength = 0;
            BOOL parsed = nw_framer_parse_input(inputFramer, 12, 12, NULL, ^size_t(uint8_t *buffer,
                                                                                   size_t bufferLength,
                                                                                   bool isComplete) {
                (void)isComplete;
                if (!buffer || bufferLength < 12) {
                    return 0;
                }
                memcpy(&wireType, buffer, sizeof(wireType));
                memcpy(&actorOptions, buffer + 4, sizeof(actorOptions));
                memcpy(&bodyLength, buffer + 8, sizeof(bodyLength));
                parsedHeader = YES;
                return 12;
            });
            if (!parsed || !parsedHeader) {
                return 12;
            }

            nw_framer_message_t message = nw_framer_message_create(inputFramer);
            nw_framer_message_set_object_value(message, kActorTypeKey, @(LogicalTypeForActorWireType(wireType)));
            nw_framer_message_set_object_value(message, kActorOptionsKey, @((NSInteger)actorOptions));
            if (!nw_framer_deliver_input_no_copy(inputFramer, bodyLength, message, true)) {
                return bodyLength;
            }
            return 0;
        });

        nw_framer_set_output_handler(framer, ^(nw_framer_t outputFramer,
                                               nw_framer_message_t message,
                                               size_t messageLength,
                                               bool isComplete) {
            (void)isComplete;
            NSInteger actorType = IntegerObjectValue(message, kActorTypeKey, 0);
            NSInteger actorOptions = IntegerObjectValue(message, kActorOptionsKey, 0);
            uint32_t header[3] = {
                ActorWireTypeForLogicalType(actorType),
                (uint32_t)actorOptions,
                (uint32_t)messageLength,
            };
            nw_framer_write_output(outputFramer, (const uint8_t *)header, sizeof(header));
            nw_framer_write_output_no_copy(outputFramer, messageLength);
        });
        return nw_framer_start_result_ready;
    });
}

static nw_protocol_definition_t CopyAppleActorDefinitionIfAvailable(void) {
    if (nw_protocol_copy_definition_for_identifier == NULL) {
        return NULL;
    }
    return nw_protocol_copy_definition_for_identifier(kActorFramerIdentifier);
}

typedef NS_ENUM(NSInteger, ProbeTransport) {
    ProbeTransportApplicationService,
    ProbeTransportTcp,
    ProbeTransportTls,
    ProbeTransportQuic,
    ProbeTransportApplicationServiceQuic,
};

static NSArray<NSString *> *gQuicApplicationProtocols = nil;

static void ConfigureTLSVerifyAny(sec_protocol_options_t secOptions) {
    sec_protocol_options_set_verify_block(secOptions,
                                          ^(sec_protocol_metadata_t metadata,
                                            sec_trust_t trustRef,
                                            sec_protocol_verify_complete_t complete) {
        (void)metadata;
        (void)trustRef;
        complete(true);
    },
                                          dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0));
}

static void ConfigurePAKEChallengeLogger(sec_protocol_options_t secOptions) {
    typedef void (^PAKEChallengeBlock)(sec_protocol_metadata_t metadata,
                                       id offeredIdentity,
                                       void (^complete)(sec_identity_t identity));
    typedef void (*SetPAKEChallengeBlockFn)(sec_protocol_options_t options,
                                            PAKEChallengeBlock block,
                                            dispatch_queue_t queue);
    SetPAKEChallengeBlockFn setPAKEChallengeBlock =
        (SetPAKEChallengeBlockFn)dlsym(RTLD_DEFAULT, "sec_protocol_options_set_pake_challenge_block");
    if (!setPAKEChallengeBlock) {
        puts("sec_protocol_options_set_pake_challenge_block unavailable");
        return;
    }
    setPAKEChallengeBlock(secOptions,
                          ^(sec_protocol_metadata_t metadata,
                            id offeredIdentity,
                            void (^complete)(sec_identity_t identity)) {
        (void)metadata;
        NSString *client = nil;
        NSString *server = nil;
        unsigned scheme = 0;
        if ([offeredIdentity respondsToSelector:NSSelectorFromString(@"client_identity")]) {
            client = ((id (*)(id, SEL))objc_msgSend)(offeredIdentity, NSSelectorFromString(@"client_identity"));
        }
        if ([offeredIdentity respondsToSelector:NSSelectorFromString(@"server_identity")]) {
            server = ((id (*)(id, SEL))objc_msgSend)(offeredIdentity, NSSelectorFromString(@"server_identity"));
        }
        if ([offeredIdentity respondsToSelector:NSSelectorFromString(@"pake_scheme")]) {
            typedef unsigned short (*SchemeFn)(id, SEL);
            SchemeFn schemeFn = (SchemeFn)[offeredIdentity methodForSelector:NSSelectorFromString(@"pake_scheme")];
            scheme = schemeFn(offeredIdentity, NSSelectorFromString(@"pake_scheme"));
        }
        printf("pake challenge offered=%s client=%s server=%s scheme=%u\n",
               offeredIdentity ? [[offeredIdentity description] UTF8String] : "nil",
               client.UTF8String ?: "",
               server.UTF8String ?: "",
               scheme);
        NSString *mode = EnvironmentString("MACOLINUX_PAKE_MODE") ?: @"log";
        if ([mode isEqualToString:@"off"] || [mode isEqualToString:@"disable"]) {
            puts("pake challenge completion=NULL (disabled)");
            complete(NULL);
            return;
        }
        if ([mode isEqualToString:@"respond"]) {
            sec_identity_t identity = CreateClientPAKEIdentity(client, server);
            printf("pake challenge completion=%s\n", identity ? "client-identity" : "NULL");
            complete(identity);
            return;
        }
        puts("pake challenge completion=NULL (log-only)");
        complete(NULL);
    },
                          dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0));
}

static void ApplyRequiredInterface(nw_parameters_t parameters, NSString *interfaceName) {
    if (interfaceName.length == 0 ||
        [interfaceName isEqualToString:@"-"] ||
        [interfaceName isEqualToString:@"any"]) {
        return;
    }

    typedef nw_interface_t (*CreateInterfaceWithNameFn)(const char *);
    CreateInterfaceWithNameFn createInterfaceWithName =
        (CreateInterfaceWithNameFn)dlsym(RTLD_DEFAULT, "nw_interface_create_with_name");
    if (!createInterfaceWithName) {
        puts("nw_interface_create_with_name unavailable");
        return;
    }

    nw_interface_t interface = createInterfaceWithName(interfaceName.UTF8String);
    if (!interface) {
        printf("failed to create required interface=%s\n", interfaceName.UTF8String);
        return;
    }
    nw_parameters_require_interface(parameters, interface);
    printf("required interface=%s\n", [[(id)interface description] UTF8String]);
}

static nw_parameters_t CreateParametersWithActorFramer(nw_protocol_definition_t definition,
                                                       ProbeTransport transport,
                                                       BOOL prependFramer,
                                                       NSString *requiredInterfaceName) {
    nw_parameters_t parameters = NULL;
    switch (transport) {
        case ProbeTransportApplicationService:
            parameters = nw_parameters_create_application_service();
            break;
        case ProbeTransportTcp:
            parameters = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
            break;
        case ProbeTransportTls:
            parameters = nw_parameters_create_secure_tcp(^(nw_protocol_options_t options) {
                sec_protocol_options_t secOptions = nw_tls_copy_sec_protocol_options(options);
                ConfigureTLSVerifyAny(secOptions);
                ConfigurePAKEChallengeLogger(secOptions);
            }, NW_PARAMETERS_DEFAULT_CONFIGURATION);
            break;
        case ProbeTransportQuic:
            parameters = nw_parameters_create_quic(^(nw_protocol_options_t options) {
                sec_protocol_options_t secOptions = nw_quic_copy_sec_protocol_options(options);
                ConfigureTLSVerifyAny(secOptions);
                ConfigurePAKEChallengeLogger(secOptions);
                for (NSString *applicationProtocol in gQuicApplicationProtocols ?: @[]) {
                    nw_quic_add_tls_application_protocol(options, applicationProtocol.UTF8String);
                }
            });
            break;
        case ProbeTransportApplicationServiceQuic:
            if (nw_parameters_create_application_service_quic) {
                parameters = nw_parameters_create_application_service_quic();
            }
            if (!parameters && nw_parameters_create_application_service_quic_using_identity) {
                parameters = nw_parameters_create_application_service_quic_using_identity(NULL);
            }
            if (!parameters) {
                fprintf(stderr, "application-service QUIC parameters are unavailable\n");
                parameters = nw_parameters_create_quic(^(nw_protocol_options_t options) {
                    sec_protocol_options_t secOptions = nw_quic_copy_sec_protocol_options(options);
                    ConfigureTLSVerifyAny(secOptions);
                    ConfigurePAKEChallengeLogger(secOptions);
                });
            }
            break;
    }
    ApplyAttributedBundleIdentifier(parameters);
    nw_parameters_set_include_peer_to_peer(parameters, true);
    ApplyRequiredInterface(parameters, requiredInterfaceName);
    if (!prependFramer) {
        return parameters;
    }
    nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(parameters);
    nw_protocol_options_t options = nw_framer_create_options(definition);
    nw_protocol_stack_prepend_application_protocol(stack, options);
    return parameters;
}

static nw_content_context_t CreateActorContext(nw_protocol_definition_t definition, NSInteger actorType, NSInteger actorOptions) {
    nw_framer_message_t message = nw_framer_protocol_create_message(definition);
    nw_framer_message_set_object_value(message, kActorTypeKey, @(actorType));
    nw_framer_message_set_object_value(message, kActorOptionsKey, @(actorOptions));

    nw_content_context_t context = nw_content_context_create("ActorSystemWireProtocol");
    nw_content_context_set_metadata_for_protocol(context, (nw_protocol_metadata_t)message);
    return context;
}

static const char *TransportName(ProbeTransport transport) {
    switch (transport) {
        case ProbeTransportApplicationService: return "appsvc";
        case ProbeTransportTcp: return "tcp";
        case ProbeTransportTls: return "tls";
        case ProbeTransportQuic:
            if ((gQuicApplicationProtocols ?: @[]).count == 0) {
                return "quic";
            }
            return "quic+alpn";
        case ProbeTransportApplicationServiceQuic: return "appsvc-quic";
    }
}

static ProbeTransport TransportFromArgument(const char *value, ProbeTransport defaultTransport) {
    if (!value) {
        return defaultTransport;
    }
    if (strcmp(value, "tcp") == 0) {
        return ProbeTransportTcp;
    }
    if (strcmp(value, "tls") == 0) {
        return ProbeTransportTls;
    }
    if (strcmp(value, "quic") == 0) {
        gQuicApplicationProtocols = @[];
        return ProbeTransportQuic;
    }
    if (strncmp(value, "quic:", 5) == 0) {
        NSString *alpnList = [NSString stringWithUTF8String:value + 5] ?: @"";
        NSArray<NSString *> *parts = [alpnList componentsSeparatedByString:@","];
        NSMutableArray<NSString *> *filtered = [NSMutableArray array];
        for (NSString *part in parts) {
            if (part.length > 0) {
                [filtered addObject:part];
            }
        }
        gQuicApplicationProtocols = filtered;
        return ProbeTransportQuic;
    }
    if (strcmp(value, "appsvc-quic") == 0) {
        return ProbeTransportApplicationServiceQuic;
    }
    return ProbeTransportApplicationService;
}

static NSData *JSONDataFromObject(id object) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:&error];
    if (!data) {
        fprintf(stderr, "failed to encode JSON data: %s\n", error.description.UTF8String);
    }
    return data;
}

static NSData *BrowserPinPairingCustomService(void) {
    return JSONDataFromObject(@{
        @"pairingType": @{@"pin": @{}},
        @"preferredPairingTypes": @[@{@"pin": @{}}],
    });
}

static NSData *BrowserPairingCustomServiceFromMode(NSString *mode) {
    if (mode.length == 0 || [mode isEqualToString:@"pin"] || [mode isEqualToString:@"both"]) {
        return BrowserPinPairingCustomService();
    }
    if ([mode isEqualToString:@"none"]) {
        return nil;
    }
    if ([mode isEqualToString:@"empty"]) {
        return [NSData data];
    }
    if ([mode isEqualToString:@"pairing-only"]) {
        return JSONDataFromObject(@{@"pairingType": @{@"pin": @{}}});
    }
    if ([mode isEqualToString:@"preferred-only"]) {
        return JSONDataFromObject(@{@"preferredPairingTypes": @[@{@"pin": @{}}]});
    }
    if ([mode hasPrefix:@"json:"]) {
        return [[mode substringFromIndex:[@"json:" length]] dataUsingEncoding:NSUTF8StringEncoding];
    }
    if ([mode hasPrefix:@"hex:"]) {
        return HexDataFromString([mode substringFromIndex:[@"hex:" length]]);
    }
    if ([mode hasPrefix:@"b64:"]) {
        return [[NSData alloc] initWithBase64EncodedString:[mode substringFromIndex:[@"b64:" length]] options:0];
    }
    fprintf(stderr, "unknown browse custom-service mode: %s\n", mode.UTF8String);
    return nil;
}

static nw_browse_descriptor_t CreateApplicationServiceBrowseDescriptor(NSString *serviceName, NSString *bundleID) {
    if (bundleID.length > 0) {
        typedef nw_browse_descriptor_t (*CreateWithBundleFn)(const char *, const char *);
        CreateWithBundleFn createWithBundle =
            (CreateWithBundleFn)dlsym(RTLD_DEFAULT, "nw_browse_descriptor_create_application_service_with_bundle_id");
        if (createWithBundle) {
            return createWithBundle(serviceName.UTF8String, bundleID.UTF8String);
        }
        puts("nw_browse_descriptor_create_application_service_with_bundle_id unavailable; using public constructor");
    }
    return nw_browse_descriptor_create_application_service(serviceName.UTF8String);
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
    printf("browse customServiceBytes=%lu\n", (unsigned long)customService.length);
    return YES;
}

static BOOL SetBrowseDescriptorEndpointsOnly(nw_browse_descriptor_t descriptor, BOOL endpointsOnly) {
    typedef void (*SetEndpointsOnlyFn)(nw_browse_descriptor_t, bool);
    SetEndpointsOnlyFn setEndpointsOnly =
        (SetEndpointsOnlyFn)dlsym(RTLD_DEFAULT, "nw_browse_descriptor_set_discover_application_service_endpoints_only");
    if (!setEndpointsOnly) {
        puts("nw_browse_descriptor_set_discover_application_service_endpoints_only unavailable");
        return NO;
    }
    setEndpointsOnly(descriptor, endpointsOnly);
    printf("browse endpointsOnly=%s\n", endpointsOnly ? "true" : "false");
    return YES;
}

static BOOL SetBrowseDescriptorUInt32Option(nw_browse_descriptor_t descriptor,
                                            const char *symbolName,
                                            const char *label,
                                            uint32_t value,
                                            BOOL shouldSet) {
    if (!shouldSet) {
        return YES;
    }
    typedef void (*SetUInt32Fn)(nw_browse_descriptor_t, uint32_t);
    SetUInt32Fn setValue = (SetUInt32Fn)dlsym(RTLD_DEFAULT, symbolName);
    if (!setValue) {
        printf("%s unavailable\n", symbolName);
        return NO;
    }
    setValue(descriptor, value);
    printf("browse %s=0x%08x\n", label, value);
    return YES;
}

typedef void (^ReceiveContentHandler)(NSData *content);

static void ReceiveLoop(nw_connection_t connection, nw_protocol_definition_t definition, ReceiveContentHandler handler) {
    nw_connection_receive(connection, 1, 4096, ^(dispatch_data_t content,
                                                nw_content_context_t context,
                                                bool isComplete,
                                                nw_error_t error) {
        NSMutableData *combined = [NSMutableData data];
        if (context) {
            nw_protocol_metadata_t metadata = nw_content_context_copy_protocol_metadata(context, definition);
            if (metadata) {
                nw_framer_message_t message = (nw_framer_message_t)metadata;
                NSInteger actorType = IntegerObjectValue(message, kActorTypeKey, -1);
                NSInteger actorOptions = IntegerObjectValue(message, kActorOptionsKey, -1);
                printf("recv actorType=%ld actorOptions=%ld\n", (long)actorType, (long)actorOptions);
            }
        }
        if (content) {
            __block size_t total = 0;
            dispatch_data_apply(content, ^bool(dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
                (void)region;
                (void)offset;
                total += size;
                [combined appendBytes:buffer length:size];
                printf("recv %zu bytes:", size);
                const uint8_t *bytes = (const uint8_t *)buffer;
                for (size_t i = 0; i < size; i++) {
                    printf(" %02x", bytes[i]);
                }
                printf("\n");
                return true;
            });
            if (total == 0) {
                puts("recv empty content");
            }
        }
        if (handler && combined.length > 0) {
            handler(combined);
        }
        if (error) {
            printf("recv error=%s\n", [[(id)error description] UTF8String]);
            return;
        }
        if (isComplete) {
            puts("recv complete");
            if (combined.length == 0) {
                return;
            }
        }
        ReceiveLoop(connection, definition, handler);
    });
}

static int RunConnection(nw_endpoint_t endpoint,
                         const char *targetDescription,
                         NSTimeInterval seconds,
                         NSInteger actorType,
                         NSInteger actorOptions,
                         NSString *payloadMode,
                         ProbeTransport transport,
                         BOOL prependFramer,
                         BOOL preferAppleDefinition,
                         BOOL passThroughDefinition,
                         NSString *requiredInterfaceName) {
    BOOL pairVerifyM3Sequence = [payloadMode hasPrefix:@"pairverify-m3-sequence:"];
    BOOL remoteCallSequence = [payloadMode hasPrefix:@"remote-call-sequence:"];
    NSMutableDictionary<NSString *, NSString *> *pairVerifyM3State = nil;
    NSData *payload = pairVerifyM3Sequence
        ? PairVerifyM3SequenceStartPayload(payloadMode, &pairVerifyM3State)
        : PayloadFromMode(payloadMode);
    if (!payload) {
        fprintf(stderr, "invalid payload mode: %s\n", payloadMode.UTF8String);
        return 2;
    }
    BOOL pairVerifySequence = [payloadMode hasPrefix:@"pairverify-sequence:"];

    const char *definitionSource = "actor";
    nw_protocol_definition_t definition = NULL;
    if (preferAppleDefinition) {
        definition = CopyAppleActorDefinitionIfAvailable();
        if (definition) {
            definitionSource = "apple";
        } else {
            definitionSource = "custom/apple-unavailable";
        }
    }
    if (!definition) {
        definition = passThroughDefinition ? CreatePassThroughActorDefinition() : CreateActorWireDefinition();
        if (passThroughDefinition) {
            definitionSource = "passthrough";
        }
    }

    nw_parameters_t parameters = CreateParametersWithActorFramer(definition, transport, prependFramer, requiredInterfaceName);
    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    dispatch_queue_t queue = dispatch_queue_create("macolinux.network-actor-framer-probe", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);

    printf("%s seconds=%.1f actorType=%ld actorOptions=%ld payload=%s payloadBytes=%lu parameters=%s framer=%s definition=%s interface=%s\n",
           targetDescription, seconds, (long)actorType, (long)actorOptions,
           payloadMode.UTF8String, (unsigned long)payload.length,
           TransportName(transport), prependFramer ? "stack" : "nostack",
           definitionSource,
           requiredInterfaceName.length > 0 ? requiredInterfaceName.UTF8String : "any");

    nw_connection_set_queue(connection, queue);
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
        printf("connection state=%s", ConnectionStateName(state));
        if (error) {
            printf(" error=%s", [[(id)error description] UTF8String]);
        }
        printf("\n");

        if (state == nw_connection_state_ready) {
            __block BOOL sentPairVerifyProcess = NO;
            __block BOOL sentRemoteCallSequenceSecond = NO;
            __block NSInteger pairVerifyM3Step = 0;
            __block NSString *pairVerifyM3SessionID = nil;
            ReceiveLoop(connection, definition, ^(NSData *replyContent) {
                if (remoteCallSequence) {
                    if (sentRemoteCallSequenceSecond) {
                        return;
                    }
                    NSData *secondPayload = RemoteCallSequenceSecondPayload(payloadMode);
                    if (!secondPayload) {
                        puts("remote-call-sequence: failed to build second payload");
                        return;
                    }
                    sentRemoteCallSequenceSecond = YES;
                    printf("remote-call-sequence: secondPayloadBytes=%lu\n",
                           (unsigned long)secondPayload.length);
                    nw_content_context_t secondContext = CreateActorContext(definition, actorType, actorOptions);
                    dispatch_data_t secondContent = dispatch_data_create(secondPayload.bytes,
                                                                         secondPayload.length,
                                                                         queue,
                                                                         DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                    nw_connection_send(connection, secondContent, secondContext, true, ^(nw_error_t secondSendError) {
                        if (secondSendError) {
                            printf("remote-call-sequence second send error=%s\n", [[(id)secondSendError description] UTF8String]);
                        } else {
                            printf("remote-call-sequence second send complete bytes=%lu\n", (unsigned long)secondPayload.length);
                        }
                    });
                    return;
                }
                if (pairVerifyM3Sequence) {
                    if (pairVerifyM3Step == 0) {
                        NSString *sessionID = ExtractJSONUUID(replyContent);
                        if (!sessionID) {
                            puts("pairverify-m3-sequence: no UUID found in start reply");
                            return;
                        }
                        NSData *processPayload = PairVerifyM3SequenceM1Payload(payloadMode, sessionID, pairVerifyM3State);
                        if (!processPayload) {
                            puts("pairverify-m3-sequence: failed to build M1 process payload");
                            return;
                        }
                        pairVerifyM3Step = 1;
                        pairVerifyM3SessionID = sessionID;
                        printf("pairverify-m3-sequence: sessionID=%s m1PayloadBytes=%lu\n",
                               sessionID.UTF8String, (unsigned long)processPayload.length);
                        nw_content_context_t processContext = CreateActorContext(definition, actorType, actorOptions);
                        dispatch_data_t processContent = dispatch_data_create(processPayload.bytes,
                                                                              processPayload.length,
                                                                              queue,
                                                                              DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                        nw_connection_send(connection, processContent, processContext, true, ^(nw_error_t processSendError) {
                            if (processSendError) {
                                printf("pairverify-m3-sequence M1 send error=%s\n", [[(id)processSendError description] UTF8String]);
                            } else {
                                printf("pairverify-m3-sequence M1 send complete bytes=%lu\n", (unsigned long)processPayload.length);
                            }
                        });
                        return;
                    }
                    if (pairVerifyM3Step == 1) {
                        NSData *m2 = ExtractJSONBase64Data(replyContent);
                        if (!m2) {
                            puts("pairverify-m3-sequence: no base64 M2 data found in process reply");
                            return;
                        }
                        NSData *processPayload = PairVerifyM3SequenceM3Payload(payloadMode, pairVerifyM3SessionID, m2, pairVerifyM3State);
                        if (!processPayload) {
                            puts("pairverify-m3-sequence: failed to build M3 process payload");
                            return;
                        }
                        pairVerifyM3Step = 2;
                        printf("pairverify-m3-sequence: m2Bytes=%lu m3PayloadBytes=%lu\n",
                               (unsigned long)m2.length, (unsigned long)processPayload.length);
                        nw_content_context_t processContext = CreateActorContext(definition, actorType, actorOptions);
                        dispatch_data_t processContent = dispatch_data_create(processPayload.bytes,
                                                                              processPayload.length,
                                                                              queue,
                                                                              DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                        nw_connection_send(connection, processContent, processContext, true, ^(nw_error_t processSendError) {
                            if (processSendError) {
                                printf("pairverify-m3-sequence M3 send error=%s\n", [[(id)processSendError description] UTF8String]);
                            } else {
                                printf("pairverify-m3-sequence M3 send complete bytes=%lu\n", (unsigned long)processPayload.length);
                            }
                        });
                        return;
                    }
                    return;
                }
                if (!pairVerifySequence || sentPairVerifyProcess) {
                    return;
                }
                NSString *sessionID = ExtractJSONUUID(replyContent);
                if (!sessionID) {
                    puts("pairverify-sequence: no UUID found in first reply");
                    return;
                }
                NSData *processPayload = PairVerifySequenceProcessPayload(payloadMode, sessionID);
                if (!processPayload) {
                    puts("pairverify-sequence: failed to build process payload");
                    return;
                }
                sentPairVerifyProcess = YES;
                printf("pairverify-sequence: sessionID=%s processPayloadBytes=%lu\n",
                       sessionID.UTF8String, (unsigned long)processPayload.length);
                nw_content_context_t processContext = CreateActorContext(definition, actorType, actorOptions);
                dispatch_data_t processContent = dispatch_data_create(processPayload.bytes,
                                                                      processPayload.length,
                                                                      queue,
                                                                      DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                nw_connection_send(connection, processContent, processContext, true, ^(nw_error_t processSendError) {
                    if (processSendError) {
                        printf("pairverify-sequence process send error=%s\n", [[(id)processSendError description] UTF8String]);
                    } else {
                        printf("pairverify-sequence process send complete bytes=%lu\n", (unsigned long)processPayload.length);
                    }
                });
            });
            nw_content_context_t context = CreateActorContext(definition, actorType, actorOptions);
            dispatch_data_t content = dispatch_data_create(payload.bytes, payload.length, queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
            nw_connection_send(connection, content, context, true, ^(nw_error_t sendError) {
                if (sendError) {
                    printf("send error=%s\n", [[(id)sendError description] UTF8String]);
                } else {
                    printf("send complete bytes=%lu\n", (unsigned long)payload.length);
                }
            });
        } else if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
            dispatch_semaphore_signal(done);
        }
    });

    nw_connection_start(connection);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        puts("timeout/cancel");
        nw_connection_cancel(connection);
        dispatch_semaphore_signal(done);
    });
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    return 0;
}

static int RunConnectService(int argc, const char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s connect-service NAME TYPE DOMAIN [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [appsvc|tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [INTERFACE|any]\n", argv[0]);
        fprintf(stderr, "payload modes: empty, zero, rpnw-control, hex:<bytes>, b64:<base64>, file:<path>, text:<utf8>, remote-call:CALL_ID|ACTOR_NAME|ACTOR_IDENTIFIER|TARGET[|OPTIONS[|arg-hex:<bytes>|arg-b64:<base64>|arg-text:<utf8>|arg-json-string:<utf8>|arg-json-data-b64:<base64>|arg-json-data-hex:<bytes>|arg-json-bool:true|arg-json-bool:false|arg-empty...]], pairverify-sequence:CALL_ID_START|CALL_ID_PROCESS|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|M1_HEX, pairverify-m3-sequence:CALL_ID_START|CALL_ID_M1|CALL_ID_M3|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|HELPER_PATH|IDENTITY_PATH\n");
        return 2;
    }

    const char *name = argv[2];
    const char *type = argv[3];
    const char *domain = argv[4];
    NSTimeInterval seconds = argc >= 6 ? atof(argv[5]) : 20.0;
    NSInteger actorType = argc >= 7 ? strtol(argv[6], NULL, 0) : 1;
    NSInteger actorOptions = argc >= 8 ? strtol(argv[7], NULL, 0) : 0;
    NSString *payloadMode = argc >= 9 ? [NSString stringWithUTF8String:argv[8]] : @"empty";
    ProbeTransport transport = TransportFromArgument(argc >= 10 ? argv[9] : NULL, ProbeTransportApplicationService);
    BOOL prependFramer = argc < 11 || strcmp(argv[10], "nostack") != 0;
    BOOL preferAppleDefinition = argc >= 12 && strcmp(argv[11], "apple") == 0;
    BOOL passThroughDefinition = argc >= 12 && strcmp(argv[11], "passthrough") == 0;
    NSString *requiredInterfaceName = argc >= 13 ? [NSString stringWithUTF8String:argv[12]] : nil;

    nw_endpoint_t endpoint = nw_endpoint_create_bonjour_service(name, type, domain);
    char description[512];
    snprintf(description, sizeof(description), "connect-service name=%s type=%s domain=%s", name, type, domain);
    return RunConnection(endpoint, description, seconds, actorType, actorOptions, payloadMode,
                         transport, prependFramer, preferAppleDefinition, passThroughDefinition,
                         requiredInterfaceName);
}

static int RunConnectHost(int argc, const char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s connect-host HOST PORT [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [INTERFACE|any]\n", argv[0]);
        fprintf(stderr, "payload modes: empty, zero, rpnw-control, hex:<bytes>, b64:<base64>, file:<path>, text:<utf8>, remote-call:CALL_ID|ACTOR_NAME|ACTOR_IDENTIFIER|TARGET[|OPTIONS[|arg-hex:<bytes>|arg-b64:<base64>|arg-text:<utf8>|arg-json-string:<utf8>|arg-json-data-b64:<base64>|arg-json-data-hex:<bytes>|arg-json-bool:true|arg-json-bool:false|arg-empty...]], pairverify-sequence:CALL_ID_START|CALL_ID_PROCESS|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|M1_HEX, pairverify-m3-sequence:CALL_ID_START|CALL_ID_M1|CALL_ID_M3|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|HELPER_PATH|IDENTITY_PATH\n");
        return 2;
    }

    const char *host = argv[2];
    const char *port = argv[3];
    NSTimeInterval seconds = argc >= 5 ? atof(argv[4]) : 20.0;
    NSInteger actorType = argc >= 6 ? strtol(argv[5], NULL, 0) : 1;
    NSInteger actorOptions = argc >= 7 ? strtol(argv[6], NULL, 0) : 0;
    NSString *payloadMode = argc >= 8 ? [NSString stringWithUTF8String:argv[7]] : @"empty";
    ProbeTransport transport = TransportFromArgument(argc >= 9 ? argv[8] : NULL, ProbeTransportTcp);
    if (transport == ProbeTransportApplicationService) {
        transport = ProbeTransportTcp;
    }
    BOOL prependFramer = argc < 10 || strcmp(argv[9], "nostack") != 0;
    BOOL preferAppleDefinition = argc >= 11 && strcmp(argv[10], "apple") == 0;
    BOOL passThroughDefinition = argc >= 11 && strcmp(argv[10], "passthrough") == 0;
    NSString *requiredInterfaceName = argc >= 12 ? [NSString stringWithUTF8String:argv[11]] : nil;

    nw_endpoint_t endpoint = nw_endpoint_create_host(host, port);
    char description[512];
    snprintf(description, sizeof(description), "connect-host host=%s port=%s", host, port);
    return RunConnection(endpoint, description, seconds, actorType, actorOptions, payloadMode,
                         transport, prependFramer, preferAppleDefinition, passThroughDefinition,
                         requiredInterfaceName);
}

static int RunConnectApplicationService(int argc, const char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s connect-appsvc NAME [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [appsvc|tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [INTERFACE|any]\n", argv[0]);
        fprintf(stderr, "payload modes: empty, zero, rpnw-control, hex:<bytes>, b64:<base64>, file:<path>, text:<utf8>, remote-call:CALL_ID|ACTOR_NAME|ACTOR_IDENTIFIER|TARGET[|OPTIONS[|arg-hex:<bytes>|arg-b64:<base64>|arg-text:<utf8>|arg-json-string:<utf8>|arg-json-data-b64:<base64>|arg-json-data-hex:<bytes>|arg-json-bool:true|arg-json-bool:false|arg-empty...]], pairverify-sequence:CALL_ID_START|CALL_ID_PROCESS|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|M1_HEX, pairverify-m3-sequence:CALL_ID_START|CALL_ID_M1|CALL_ID_M3|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|HELPER_PATH|IDENTITY_PATH\n");
        return 2;
    }
    if (!nw_endpoint_create_application_service) {
        fprintf(stderr, "nw_endpoint_create_application_service is unavailable\n");
        return 2;
    }

    const char *name = argv[2];
    NSTimeInterval seconds = argc >= 4 ? atof(argv[3]) : 20.0;
    NSInteger actorType = argc >= 5 ? strtol(argv[4], NULL, 0) : 1;
    NSInteger actorOptions = argc >= 6 ? strtol(argv[5], NULL, 0) : 0;
    NSString *payloadMode = argc >= 7 ? [NSString stringWithUTF8String:argv[6]] : @"empty";
    ProbeTransport transport = TransportFromArgument(argc >= 8 ? argv[7] : NULL, ProbeTransportApplicationServiceQuic);
    BOOL prependFramer = argc < 9 || strcmp(argv[8], "nostack") != 0;
    BOOL preferAppleDefinition = argc >= 10 && strcmp(argv[9], "apple") == 0;
    BOOL passThroughDefinition = argc >= 10 && strcmp(argv[9], "passthrough") == 0;
    NSString *requiredInterfaceName = argc >= 11 ? [NSString stringWithUTF8String:argv[10]] : nil;

    nw_endpoint_t endpoint = nw_endpoint_create_application_service(name);
    char description[512];
    snprintf(description, sizeof(description), "connect-appsvc name=%s", name);
    return RunConnection(endpoint, description, seconds, actorType, actorOptions, payloadMode,
                         transport, prependFramer, preferAppleDefinition, passThroughDefinition,
                         requiredInterfaceName);
}

static int RunBrowseApplicationService(int argc, const char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s browse-appsvc SERVICE BUNDLE_ID [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [appsvc|tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [endpoints-only|all] [INTERFACE|any] [BROWSE_SCOPE_HEX|default] [DEVICE_TYPES_HEX|default] [pin|both|pairing-only|preferred-only|empty|none|json:...|hex:...|b64:...]\n", argv[0]);
        fprintf(stderr, "payload modes: empty, zero, rpnw-control, hex:<bytes>, b64:<base64>, file:<path>, text:<utf8>, remote-call:CALL_ID|ACTOR_NAME|ACTOR_IDENTIFIER|TARGET[|OPTIONS[|arg-hex:<bytes>|arg-b64:<base64>|arg-text:<utf8>|arg-json-string:<utf8>|arg-json-data-b64:<base64>|arg-json-data-hex:<bytes>|arg-json-bool:true|arg-json-bool:false|arg-empty...]], pairverify-sequence:CALL_ID_START|CALL_ID_PROCESS|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|M1_HEX, pairverify-m3-sequence:CALL_ID_START|CALL_ID_M1|CALL_ID_M3|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|HELPER_PATH|IDENTITY_PATH\n");
        return 2;
    }

    NSString *serviceName = [NSString stringWithUTF8String:argv[2]];
    NSString *bundleID = [NSString stringWithUTF8String:argv[3]];
    NSTimeInterval seconds = argc >= 5 ? atof(argv[4]) : 20.0;
    NSInteger actorType = argc >= 6 ? strtol(argv[5], NULL, 0) : 3;
    NSInteger actorOptions = argc >= 7 ? strtol(argv[6], NULL, 0) : 0;
    NSString *payloadMode = argc >= 8 ? [NSString stringWithUTF8String:argv[7]] : @"empty";
    ProbeTransport transport = TransportFromArgument(argc >= 9 ? argv[8] : NULL, ProbeTransportApplicationServiceQuic);
    BOOL prependFramer = argc < 10 || strcmp(argv[9], "nostack") != 0;
    BOOL preferAppleDefinition = argc >= 11 && strcmp(argv[10], "apple") == 0;
    BOOL passThroughDefinition = argc >= 11 && strcmp(argv[10], "passthrough") == 0;
    BOOL endpointsOnly = argc < 12 || strcmp(argv[11], "all") != 0;
    NSString *requiredInterfaceName = argc >= 13 ? [NSString stringWithUTF8String:argv[12]] : nil;
    BOOL setBrowseScope = argc >= 14 && strcmp(argv[13], "default") != 0 && strcmp(argv[13], "-") != 0;
    uint32_t browseScope = setBrowseScope ? (uint32_t)strtoul(argv[13], NULL, 0) : 0;
    BOOL setDeviceTypes = argc >= 15 && strcmp(argv[14], "default") != 0 && strcmp(argv[14], "-") != 0;
    uint32_t deviceTypes = setDeviceTypes ? (uint32_t)strtoul(argv[14], NULL, 0) : 0;
    NSString *customServiceMode = argc >= 16 ? [NSString stringWithUTF8String:argv[15]] : @"pin";

    nw_browse_descriptor_t descriptor = CreateApplicationServiceBrowseDescriptor(serviceName, bundleID);
    if (!descriptor) {
        puts("browse-appsvc: failed to create descriptor");
        return 2;
    }
    NSData *customService = BrowserPairingCustomServiceFromMode(customServiceMode);
    if (!customService && ![customServiceMode isEqualToString:@"none"]) {
        return 2;
    }
    if (!SetBrowseDescriptorCustomService(descriptor, customService)) {
        return 2;
    }
    SetBrowseDescriptorEndpointsOnly(descriptor, endpointsOnly);
    SetBrowseDescriptorUInt32Option(descriptor,
                                    "nw_browse_descriptor_set_browse_scope",
                                    "scope",
                                    browseScope,
                                    setBrowseScope);
    SetBrowseDescriptorUInt32Option(descriptor,
                                    "nw_browse_descriptor_set_device_types",
                                    "deviceTypes",
                                    deviceTypes,
                                    setDeviceTypes);

    nw_protocol_definition_t browserDefinition = CreateActorWireDefinition();
    nw_parameters_t parameters = CreateParametersWithActorFramer(browserDefinition, transport, NO, requiredInterfaceName);
    nw_browser_t browser = nw_browser_create(descriptor, parameters);
    if (!browser) {
        puts("browse-appsvc: nw_browser_create failed");
        return 2;
    }

    dispatch_queue_t queue = dispatch_queue_create("macolinux.network-actor-framer-probe.browser", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block BOOL startedConnection = NO;

    printf("browse-appsvc service=%s bundle=%s seconds=%.1f parameters=%s interface=%s descriptor=%s\n",
           serviceName.UTF8String,
           bundleID.length > 0 ? bundleID.UTF8String : "(default)",
           seconds,
           TransportName(transport),
           requiredInterfaceName.length > 0 ? requiredInterfaceName.UTF8String : "any",
           [[(id)descriptor description] UTF8String]);

    nw_browser_set_queue(browser, queue);
    nw_browser_set_state_changed_handler(browser, ^(nw_browser_state_t state, nw_error_t error) {
        printf("browser state=%s", BrowserStateName(state));
        if (error) {
            printf(" error=%s", [[(id)error description] UTF8String]);
        }
        puts("");
        if (state == nw_browser_state_failed || state == nw_browser_state_cancelled) {
            dispatch_semaphore_signal(done);
        }
    });
    nw_browser_set_browse_results_changed_handler(browser, ^(nw_browse_result_t oldResult,
                                                             nw_browse_result_t newResult,
                                                             bool batchComplete) {
        nw_browse_result_change_t changes = nw_browse_result_get_changes(oldResult, newResult);
        nw_browse_result_t result = newResult ?: oldResult;
        nw_endpoint_t endpoint = result ? nw_browse_result_copy_endpoint(result) : nil;
        printf("browser result changes=0x%llx batchComplete=%s endpoint=%s\n",
               (unsigned long long)changes,
               batchComplete ? "yes" : "no",
               endpoint ? [[(id)endpoint description] UTF8String] : "nil");
        if (result) {
            nw_txt_record_t resultTXT = nw_browse_result_copy_txt_record_object(result);
            PrintTXTRecord(@"browser result", resultTXT);
        }
        if (endpoint) {
            nw_txt_record_t endpointTXT = nw_endpoint_copy_txt_record(endpoint);
            PrintTXTRecord(@"browser endpoint", endpointTXT);
            PrintEndpointSignature(@"browser endpoint", endpoint);
        }
        if (!newResult || !endpoint || startedConnection) {
            return;
        }
        startedConnection = YES;
        nw_endpoint_t endpointForConnection = endpoint;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            char description[1024];
            snprintf(description, sizeof(description), "browse-appsvc endpoint=%s",
                     [[(id)endpointForConnection description] UTF8String]);
            int status = RunConnection(endpointForConnection,
                                       description,
                                       seconds,
                                       actorType,
                                       actorOptions,
                                       payloadMode,
                                       transport,
                                       prependFramer,
                                       preferAppleDefinition,
                                       passThroughDefinition,
                                       requiredInterfaceName);
            printf("browse-appsvc connection status=%d\n", status);
            dispatch_semaphore_signal(done);
        });
    });

    nw_browser_start(browser);
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC));
    if (dispatch_semaphore_wait(done, deadline) != 0) {
        puts("browse-appsvc timeout");
    }
    nw_browser_cancel(browser);
    return 0;
}

static int RunBrowseBonjourService(int argc, const char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s browse-service NAME_FILTER TYPE DOMAIN [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [appsvc|tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [INTERFACE|any]\n", argv[0]);
        fprintf(stderr, "payload modes: empty, zero, rpnw-control, hex:<bytes>, b64:<base64>, file:<path>, text:<utf8>, remote-call:CALL_ID|ACTOR_NAME|ACTOR_IDENTIFIER|TARGET[|OPTIONS[|arg-hex:<bytes>|arg-b64:<base64>|arg-text:<utf8>|arg-json-string:<utf8>|arg-json-data-b64:<base64>|arg-json-data-hex:<bytes>|arg-json-bool:true|arg-json-bool:false|arg-empty...]], pairverify-sequence:CALL_ID_START|CALL_ID_PROCESS|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|M1_HEX, pairverify-m3-sequence:CALL_ID_START|CALL_ID_M1|CALL_ID_M3|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|HELPER_PATH|IDENTITY_PATH\n");
        return 2;
    }

    NSString *nameFilter = [NSString stringWithUTF8String:argv[2]];
    const char *type = argv[3];
    const char *domain = argv[4];
    NSTimeInterval seconds = argc >= 6 ? atof(argv[5]) : 20.0;
    NSInteger actorType = argc >= 7 ? strtol(argv[6], NULL, 0) : 3;
    NSInteger actorOptions = argc >= 8 ? strtol(argv[7], NULL, 0) : 0;
    NSString *payloadMode = argc >= 9 ? [NSString stringWithUTF8String:argv[8]] : @"empty";
    ProbeTransport transport = TransportFromArgument(argc >= 10 ? argv[9] : NULL, ProbeTransportApplicationServiceQuic);
    BOOL prependFramer = argc < 11 || strcmp(argv[10], "nostack") != 0;
    BOOL preferAppleDefinition = argc >= 12 && strcmp(argv[11], "apple") == 0;
    BOOL passThroughDefinition = argc >= 12 && strcmp(argv[11], "passthrough") == 0;
    NSString *requiredInterfaceName = argc >= 13 ? [NSString stringWithUTF8String:argv[12]] : nil;

    nw_browse_descriptor_t descriptor = nw_browse_descriptor_create_bonjour_service(type, domain);
    nw_protocol_definition_t browserDefinition = CreateActorWireDefinition();
    nw_parameters_t parameters = CreateParametersWithActorFramer(browserDefinition, transport, NO, requiredInterfaceName);
    nw_browser_t browser = nw_browser_create(descriptor, parameters);
    if (!browser) {
        puts("browse-service: nw_browser_create failed");
        return 2;
    }

    dispatch_queue_t queue = dispatch_queue_create("macolinux.network-actor-framer-probe.bonjour-browser", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block BOOL startedConnection = NO;

    printf("browse-service nameFilter=%s type=%s domain=%s seconds=%.1f parameters=%s interface=%s descriptor=%s\n",
           nameFilter.UTF8String,
           type,
           domain,
           seconds,
           TransportName(transport),
           requiredInterfaceName.length > 0 ? requiredInterfaceName.UTF8String : "any",
           [[(id)descriptor description] UTF8String]);

    nw_browser_set_queue(browser, queue);
    nw_browser_set_state_changed_handler(browser, ^(nw_browser_state_t state, nw_error_t error) {
        printf("browser state=%s", BrowserStateName(state));
        if (error) {
            printf(" error=%s", [[(id)error description] UTF8String]);
        }
        puts("");
        if (state == nw_browser_state_failed || state == nw_browser_state_cancelled) {
            dispatch_semaphore_signal(done);
        }
    });
    nw_browser_set_browse_results_changed_handler(browser, ^(nw_browse_result_t oldResult,
                                                             nw_browse_result_t newResult,
                                                             bool batchComplete) {
        nw_browse_result_change_t changes = nw_browse_result_get_changes(oldResult, newResult);
        nw_browse_result_t result = newResult ?: oldResult;
        nw_endpoint_t endpoint = result ? nw_browse_result_copy_endpoint(result) : nil;
        NSString *endpointDescription = endpoint ? [(id)endpoint description] : @"nil";
        printf("browser result changes=0x%llx batchComplete=%s endpoint=%s\n",
               (unsigned long long)changes,
               batchComplete ? "yes" : "no",
               endpointDescription.UTF8String);
        if (result) {
            nw_txt_record_t resultTXT = nw_browse_result_copy_txt_record_object(result);
            PrintTXTRecord(@"browser result", resultTXT);
            printf("browser result interfaces=%zu\n", nw_browse_result_get_interfaces_count(result));
            nw_browse_result_enumerate_interfaces(result, ^bool(nw_interface_t interface) {
                printf("browser result interface=%s\n", [[(id)interface description] UTF8String]);
                return true;
            });
        }
        if (endpoint) {
            nw_txt_record_t endpointTXT = nw_endpoint_copy_txt_record(endpoint);
            PrintTXTRecord(@"browser endpoint", endpointTXT);
            PrintEndpointSignature(@"browser endpoint", endpoint);
        }
        if (!newResult || !endpoint || startedConnection) {
            return;
        }
        if (nameFilter.length > 0 && ![nameFilter isEqualToString:@"*"] &&
            [endpointDescription rangeOfString:nameFilter options:NSCaseInsensitiveSearch].location == NSNotFound) {
            return;
        }
        startedConnection = YES;
        nw_endpoint_t endpointForConnection = endpoint;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            char description[1024];
            snprintf(description, sizeof(description), "browse-service endpoint=%s",
                     [[(id)endpointForConnection description] UTF8String]);
            int status = RunConnection(endpointForConnection,
                                       description,
                                       seconds,
                                       actorType,
                                       actorOptions,
                                       payloadMode,
                                       transport,
                                       prependFramer,
                                       preferAppleDefinition,
                                       passThroughDefinition,
                                       requiredInterfaceName);
            printf("browse-service connection status=%d\n", status);
            dispatch_semaphore_signal(done);
        });
    });

    nw_browser_start(browser);
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC));
    if (dispatch_semaphore_wait(done, deadline) != 0) {
        puts("browse-service timeout");
    }
    nw_browser_cancel(browser);
    return 0;
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc >= 2 && strcmp(argv[1], "connect-service") == 0) {
            return RunConnectService(argc, argv);
        }
        if (argc >= 2 && strcmp(argv[1], "connect-host") == 0) {
            return RunConnectHost(argc, argv);
        }
        if (argc >= 2 && strcmp(argv[1], "connect-appsvc") == 0) {
            return RunConnectApplicationService(argc, argv);
        }
        if (argc >= 2 && strcmp(argv[1], "browse-appsvc") == 0) {
            return RunBrowseApplicationService(argc, argv);
        }
        if (argc >= 2 && strcmp(argv[1], "browse-service") == 0) {
            return RunBrowseBonjourService(argc, argv);
        }
        fprintf(stderr, "usage: %s connect-service NAME TYPE DOMAIN [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [appsvc|tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [INTERFACE|any]\n", argv[0]);
        fprintf(stderr, "       %s connect-host HOST PORT [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [INTERFACE|any]\n", argv[0]);
        fprintf(stderr, "       %s connect-appsvc NAME [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [appsvc|tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [INTERFACE|any]\n", argv[0]);
        fprintf(stderr, "       %s browse-appsvc SERVICE BUNDLE_ID [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [appsvc|tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [endpoints-only|all] [INTERFACE|any] [BROWSE_SCOPE_HEX|default] [DEVICE_TYPES_HEX|default] [pin|both|pairing-only|preferred-only|empty|none|json:...|hex:...|b64:...]\n", argv[0]);
        fprintf(stderr, "       %s browse-service NAME_FILTER TYPE DOMAIN [SECONDS] [TYPE] [OPTIONS] [PAYLOAD] [appsvc|tcp|tls|quic[:ALPN,...]|appsvc-quic] [stack|nostack] [actor|passthrough|apple] [INTERFACE|any]\n", argv[0]);
        fprintf(stderr, "payload modes: empty, zero, rpnw-control, hex:<bytes>, b64:<base64>, file:<path>, text:<utf8>, remote-call:CALL_ID|ACTOR_NAME|ACTOR_IDENTIFIER|TARGET[|OPTIONS[|arg-hex:<bytes>|arg-b64:<base64>|arg-text:<utf8>|arg-json-string:<utf8>|arg-json-data-b64:<base64>|arg-json-data-hex:<bytes>|arg-json-bool:true|arg-json-bool:false|arg-empty...]], pairverify-sequence:CALL_ID_START|CALL_ID_PROCESS|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|M1_HEX, pairverify-m3-sequence:CALL_ID_START|CALL_ID_M1|CALL_ID_M3|ACTOR_NAME|ACTOR_IDENTIFIER|CREATE_STREAM|HELPER_PATH|IDENTITY_PATH\n");
        return 2;
    }
}
