// Owned compile-only oracle. No SDK headers, app execution or imported sources.
volatile unsigned long long owned_small_words[8];
__attribute__((objc_root_class))
@interface OwnedSmall
- (signed char)c:(signed char)v;
- (unsigned char)C:(unsigned char)v;
- (short)s:(short)v;
- (unsigned short)S:(unsigned short)v;
- (int)i:(int)v;
- (unsigned int)I:(unsigned int)v;
- (_Bool)B:(_Bool)v;
- (void)mixed:(signed char)a flag:(_Bool)b shortValue:(unsigned short)c index:(int)d;
#if defined(__arm64__)
- (void)full:(char)a b:(unsigned char)b c:(short)c d:(unsigned short)d e:(int)e f:(unsigned int)f;
#endif
@end
@implementation OwnedSmall
- (signed char)c:(signed char)v { return v; }
- (unsigned char)C:(unsigned char)v { return v; }
- (short)s:(short)v { return v; }
- (unsigned short)S:(unsigned short)v { return v; }
- (int)i:(int)v { return v; }
- (unsigned int)I:(unsigned int)v { return v; }
- (_Bool)B:(_Bool)v { return v; }
- (void)mixed:(signed char)a flag:(_Bool)b shortValue:(unsigned short)c index:(int)d {
    owned_small_words[0] = (unsigned long long)self;
    owned_small_words[1] = (unsigned long long)_cmd;
    owned_small_words[2] = a; owned_small_words[3] = b;
    owned_small_words[4] = c; owned_small_words[5] = d;
}
#if defined(__arm64__)
- (void)full:(char)a b:(unsigned char)b c:(short)c d:(unsigned short)d e:(int)e f:(unsigned int)f {
    owned_small_words[0] = (unsigned long long)self;
    owned_small_words[1] = (unsigned long long)_cmd;
    owned_small_words[2] = a; owned_small_words[3] = b;
    owned_small_words[4] = c; owned_small_words[5] = d;
    owned_small_words[6] = e; owned_small_words[7] = f;
}
#endif
@end
const char *owned_small_encodings[] = {@encode(signed char), @encode(unsigned char),
    @encode(short), @encode(unsigned short), @encode(int), @encode(unsigned int), @encode(_Bool)};
const unsigned long owned_small_sizes[] = {sizeof(signed char), sizeof(unsigned char),
    sizeof(short), sizeof(unsigned short), sizeof(int), sizeof(unsigned int), sizeof(_Bool)};
