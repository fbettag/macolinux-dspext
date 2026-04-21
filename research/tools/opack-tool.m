#import <Foundation/Foundation.h>
#import <dlfcn.h>

typedef CFTypeRef (*OPACKDecodeDataFunc)(CFDataRef data, uint32_t flags, OSStatus *error);
typedef CFDataRef (*OPACKEncoderCreateDataFunc)(CFTypeRef object, uint32_t flags, OSStatus *error);

static NSData *DataFromHex(NSString *hex) {
    NSMutableData *data = [NSMutableData data];
    NSMutableString *clean = [NSMutableString stringWithCapacity:[hex length]];
    NSCharacterSet *hexChars = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"];
    for (NSUInteger i = 0; i < [hex length]; i++) {
        unichar c = [hex characterAtIndex:i];
        if ([hexChars characterIsMember:c]) {
            [clean appendFormat:@"%C", c];
        }
    }
    if ([clean length] % 2 != 0) {
        return nil;
    }
    for (NSUInteger i = 0; i < [clean length]; i += 2) {
        unsigned int byte = 0;
        NSString *part = [clean substringWithRange:NSMakeRange(i, 2)];
        [[NSScanner scannerWithString:part] scanHexInt:&byte];
        uint8_t b = (uint8_t)byte;
        [data appendBytes:&b length:1];
    }
    return data;
}

static NSString *HexFromData(NSData *data) {
    const uint8_t *bytes = data.bytes;
    NSMutableString *out = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [out appendFormat:@"%02x", bytes[i]];
    }
    return out;
}

static void PrintObject(id object) {
    if (!object) {
        puts("null");
        return;
    }

    if ([NSJSONSerialization isValidJSONObject:object]) {
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:object
                                                       options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
                                                         error:&error];
        if (json) {
            fwrite(json.bytes, 1, json.length, stdout);
            fputc('\n', stdout);
            return;
        }
    }

    printf("%s\n", [[object description] UTF8String]);
}

static void Usage(const char *argv0) {
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  %s decode HEX\n", argv0);
    fprintf(stderr, "  %s encode-json JSON\n", argv0);
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 3) {
            Usage(argv[0]);
            return 2;
        }

        void *handle = dlopen("/System/Library/PrivateFrameworks/CoreUtils.framework/CoreUtils", RTLD_NOW);
        if (!handle) {
            handle = dlopen("/System/Library/PrivateFrameworks/Rapport.framework/Rapport", RTLD_NOW);
        }
        if (!handle) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            return 1;
        }

        OPACKDecodeDataFunc OPACKDecodeData = (OPACKDecodeDataFunc)dlsym(handle, "OPACKDecodeData");
        OPACKEncoderCreateDataFunc OPACKEncoderCreateData =
            (OPACKEncoderCreateDataFunc)dlsym(handle, "OPACKEncoderCreateData");

        if (!OPACKDecodeData || !OPACKEncoderCreateData) {
            fprintf(stderr, "OPACK symbols not found\n");
            return 1;
        }

        NSString *command = [NSString stringWithUTF8String:argv[1]];
        NSString *input = [NSString stringWithUTF8String:argv[2]];

        if ([command isEqualToString:@"decode"]) {
            NSData *data = DataFromHex(input);
            if (!data) {
                fprintf(stderr, "invalid hex input\n");
                return 2;
            }
            OSStatus status = 0;
            CFTypeRef decoded = OPACKDecodeData((__bridge CFDataRef)data, 0, &status);
            if (!decoded || status != 0) {
                fprintf(stderr, "OPACKDecodeData failed: %d\n", (int)status);
                if (decoded) {
                    CFRelease(decoded);
                }
                return 1;
            }
            id object = CFBridgingRelease(decoded);
            PrintObject(object);
            return 0;
        }

        if ([command isEqualToString:@"encode-json"]) {
            NSData *json = [input dataUsingEncoding:NSUTF8StringEncoding];
            NSError *jsonError = nil;
            id object = [NSJSONSerialization JSONObjectWithData:json options:0 error:&jsonError];
            if (!object) {
                fprintf(stderr, "JSON parse failed: %s\n", [[jsonError description] UTF8String]);
                return 2;
            }
            OSStatus status = 0;
            CFDataRef encoded = OPACKEncoderCreateData((__bridge CFTypeRef)object, 0, &status);
            if (!encoded || status != 0) {
                fprintf(stderr, "OPACKEncoderCreateData failed: %d\n", (int)status);
                if (encoded) {
                    CFRelease(encoded);
                }
                return 1;
            }
            NSData *data = CFBridgingRelease(encoded);
            printf("%s\n", [HexFromData(data) UTF8String]);
            return 0;
        }

        Usage(argv[0]);
        return 2;
    }
}

