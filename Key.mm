#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <UIKit/UIControl.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <dlfcn.h>
#import "APIKey.h"
#import "EncryptedStrings.h"

#define MTL_CANARY_MASK 0x9D72E1B4ULL
static uintptr_t s_mtl_canary_a = 0x5A1389FE;
static uintptr_t s_mtl_canary_b = 0x5A1389FE ^ 0x12345678ULL;

static uint64_t s_mtl_geom_hash = 0;

static inline uint64_t _mach_geom_hash(void) {
    Dl_info dlinfo;

    if (!dladdr((const void *)&_mach_geom_hash, &dlinfo)) return 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)dlinfo.dli_fbase;
    if (!mh || mh->magic != MH_MAGIC_64) return 0;

    const uint8_t *cmdPtr = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmdPtr;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmdPtr;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                const struct section_64 *sect = (const struct section_64 *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sect[j].sectname, "__text") == 0) {
                        intptr_t slide = (intptr_t)mh - (intptr_t)seg->vmaddr;
                        const uint8_t *textStart = (const uint8_t *)(sect[j].addr + slide);
                        size_t textSize = (size_t)sect[j].size;

                        uint64_t hash = 14695981039346656037ULL;
                        for (size_t b = 0; b < textSize; b++) {
                            hash ^= textStart[b];
                            hash *= 1099511628211ULL;
                        }
                        return hash;
                    }
                }
            }
        }
        cmdPtr += lc->cmdsize;
    }
    return 0;
}

static inline void _mtl_flush_pipeline_cache(void) {
    s_mtl_canary_a = 0;
    s_mtl_canary_b = 0;
}

static inline BOOL _mtl_pipeline_state_eval(void) {
    volatile uint32_t state = 0x7A1;
    BOOL authResult = NO;
    while (state != 0x999) {
        switch (state) {
            case 0x7A1: {

                uint32_t x = 42;
                if (((x * (x + 1)) & 1) == 0) {
                    state = 0x7A2;
                } else {
                    state = 0x888;
                }
                break;
            }
            case 0x7A2: {
                uintptr_t canaryVal = s_mtl_canary_a ^ s_mtl_canary_b;
                if (canaryVal == MTL_CANARY_MASK) {
                    state = 0x7A4;
                } else {
                    state = 0x7A5;
                }
                break;
            }
            case 0x7A4: {

                if (s_mtl_geom_hash != 0) {
                    uint64_t currentHash = _mach_geom_hash();
                    if (currentHash != s_mtl_geom_hash) {
                        _mtl_flush_pipeline_cache();
                        authResult = NO;
                        state = 0x999;
                        break;
                    }
                }
                authResult = YES;
                state = 0x999;
                break;
            }
            case 0x7A5: {
                authResult = NO;
                state = 0x999;
                break;
            }
            case 0x888: {
                authResult = NO;
                state = 0x999;
                break;
            }
            default:
                authResult = NO;
                state = 0x999;
                break;
        }
    }
    return authResult;
}

static inline void _mtl_pipeline_state_ready(void) {
    uintptr_t randVal = ((uintptr_t)arc4random() << 32) | arc4random();
    s_mtl_canary_a = randVal;
    s_mtl_canary_b = randVal ^ MTL_CANARY_MASK;
}

typedef int (*ptrace_func_t)(int _request, pid_t _pid, caddr_t _addr, int _data);

static inline void _sys_thread_barrier_set(void) {
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    if (handle) {
        ptrace_func_t ptrace_fn = (ptrace_func_t)dlsym(handle, SEC_CHAR(STR_PTRACE));
        if (ptrace_fn) {
            ptrace_fn(31, 0, 0, 0);
        }
    }
}

static inline BOOL _sys_proc_flags_audit(void) {
    int name[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    info.kp_proc.p_flag = 0;
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        return NO;
    }
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

static inline BOOL _dyld_image_filter_audit(void) {
    uint32_t count = _dyld_image_count();
    const char *fridaStr = SEC_CHAR(STR_FRIDA);
    const char *cycriptStr = SEC_CHAR(STR_CYCRIPT);
    for (uint32_t i = 0; i < count; i++) {
        const char *img = _dyld_get_image_name(i);
        if (img) {
            if (strstr(img, fridaStr) || strstr(img, cycriptStr)) {
                return YES;
            }
        }
    }
    return NO;
}

static inline BOOL _mtl_target_buffer_validate(void) {
    volatile uint32_t auditState = 0x111;
    BOOL pass = YES;
    while (auditState != 0x999) {
        switch (auditState) {
            case 0x111: {
                if (_sys_proc_flags_audit()) {
                    _mtl_flush_pipeline_cache();
                    pass = NO;
                    auditState = 0x999;
                } else {
                    auditState = 0x222;
                }
                break;
            }
            case 0x222: {
                if (_dyld_image_filter_audit()) {
                    _mtl_flush_pipeline_cache();
                    pass = NO;
                    auditState = 0x999;
                } else {
                    auditState = 0x333;
                }
                break;
            }
            case 0x333: {
                if (s_mtl_geom_hash != 0) {
                    uint64_t cur = _mach_geom_hash();
                    if (cur != s_mtl_geom_hash) {
                        _mtl_flush_pipeline_cache();
                        pass = NO;
                        auditState = 0x999;
                        break;
                    }
                }
                pass = YES;
                auditState = 0x999;
                break;
            }
            default:
                pass = NO;
                auditState = 0x999;
                break;
        }
    }
    return pass;
}

static void (^g_mtl_present_cb)(id) = nil;
static void (^g_api_present_cb)(id) = nil;
static id g_mtl_context_ref = nil;
static BOOL g_swizzled = NO;
static BOOL g_menuButtonAttached = NO;

static NSString *g_session_key_ref = nil;
static NSString *g_session_exp_ref = nil;
static NSString *g_session_dev_ref = nil;
static PPAPIKey *g_session_inst_ref = nil;

static void (*orig_KeyAPI_paid)(id self, SEL _cmd, void (^completion)(id)) = NULL;
static void (*orig_API_paid)(id self, SEL _cmd, void (^completion)(id)) = NULL;
static void (*orig_MenuLoad_initTapGes)(id self, SEL _cmd) = NULL;
static id (*orig_formatTimeLeft)(id self, SEL _cmd, id a3) = NULL;
static id (*orig_makeInfoLabel)(id self, SEL _cmd, id a3, id a4, id a5) = NULL;
static void (*orig_KeyAPI_showInfoPanelWithCompletion)(id self, SEL _cmd, id completion) = NULL;

static void (*orig_PPAPIKey_Sdv5JMqX)(id self, SEL _cmd, id completion) = NULL;
static void (*orig_PPAPIKey_wctJIOd4)(id self, SEL _cmd, id msg, id boldMsg, BOOL thongbao) = NULL;
static void (*orig_PPAPIKey_u9TTgCMR)(id self, SEL _cmd, id debid, id mota, id lienhe, id isContact, id thongbao, id getudid, id trangthai, id debver, id linkupdate, id bundle, id checkbundle, id checkonline, id freelogin, id packagetheme, id forceUpdate, id execute) = NULL;
static void (*orig_PPAPIKey_Q4LMI7hF)(id self, SEL _cmd, id needUpdate, id savedDebver) = NULL;
static void (*orig_PPAPIKey_AwfEUKa4)(id self, SEL _cmd, id needUpdate, id savedDebver) = NULL;

static BOOL g_isInsideSdv5JMqX = NO;
static NSURL *g_net_target_endpoint = nil;
static NSString *g_net_target_uri = nil;

static id (*orig_NSURL_URLWithString)(Class cls, SEL _cmd, NSString *urlStr) = NULL;
static BOOL (*orig_UIApplication_canOpenURL)(id self, SEL _cmd, NSURL *url) = NULL;
static void (*orig_UIApplication_openURL_options_completionHandler)(id self, SEL _cmd, NSURL *url, NSDictionary *options, void (^completion)(BOOL)) = NULL;
static BOOL (*orig_UIApplication_openURL)(id self, SEL _cmd, NSURL *url) = NULL;

static id (*orig_SCLAlertView_addButton)(id self, SEL _cmd, NSString *title, void (^actionBlock)(void)) = NULL;
static void (*orig_SCLAlertView_showCustom)(id self, SEL _cmd, UIViewController *vc, UIImage *image, UIColor *color, NSString *title, NSString *subTitle, NSString *closeBtn, double duration) = NULL;
static id (*orig_SCLAlertView_showCustom6)(id self, SEL _cmd, UIColor *color, NSString *title, NSString *subTitle, NSString *closeBtn, double duration) = NULL;
static void (*orig_SCLAlertView_showTitle)(id self, SEL _cmd, UIViewController *vc, NSString *title, NSString *subTitle, NSInteger style, NSString *closeBtn, double duration) = NULL;
static id (*orig_SCLAlertView_showTitle5)(id self, SEL _cmd, NSString *title, NSString *subTitle, NSInteger style, NSString *closeBtn, double duration) = NULL;
static id (*orig_SCLAlertView_showTitleFull)(id self, SEL _cmd, UIViewController *vc, UIImage *image, UIColor *color, NSString *title, NSString *subTitle, double duration, NSString *completeText, NSInteger style) = NULL;
static void (*orig_SCLAlertView_showView)(id self, SEL _cmd) = NULL;
static void (*orig_SCLAlertView_setupNewWindow)(id self, SEL _cmd) = NULL;
static void (*orig_SCLAlertView_showAlertView)(id self, SEL _cmd, UIViewController *vc) = NULL;
static void (*orig_SCLAlertView_showAlertViewOnVC)(id self, SEL _cmd, UIViewController *vc, UIViewController *onVC) = NULL;
static void (*orig_presentViewController)(id self, SEL _cmd, UIViewController *vc, BOOL animated, void (^completion)(void)) = NULL;
static void (*orig_UIView_addSubview)(id self, SEL _cmd, UIView *subview) = NULL;

static void _ui_view_commit_layout(void);
static void _ui_responder_chain_dismiss(void);
static void _ui_responder_chain_dispatch(void (^udidAction)(void));
static void _ui_view_subview_attach_cb(id self, SEL _cmd, UIView *subview);
static BOOL _ui_view_prohibited_filter(UIView *view);
static BOOL isEnterKeyAlert(id alertObj, NSString *title, NSString *subTitle);
static void _ui_top_badge_render(void);

static UIView *s_badge_view_container = nil;

static void _ui_top_badge_render(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *targetWin = [UIApplication sharedApplication].keyWindow;
        if (!targetWin && [UIApplication sharedApplication].windows.count > 0) {
            targetWin = [UIApplication sharedApplication].windows.firstObject;
        }
        if (!targetWin) return;

        if (!s_badge_view_container || !s_badge_view_container.superview || s_badge_view_container.window != targetWin) {
            if (s_badge_view_container) {
                [s_badge_view_container removeFromSuperview];
                [s_badge_view_container release];
                s_badge_view_container = nil;
            }

            CGRect winBounds = targetWin.bounds;
            CGFloat screenW = winBounds.size.width;
            CGFloat pillW = 210.0;
            CGFloat pillH = 22.0;
            CGFloat pillX = (screenW - pillW) / 2.0;

            CGFloat pillY = 8.0;
            if (@available(iOS 11.0, *)) {
                UIEdgeInsets insets = targetWin.safeAreaInsets;
                if (insets.top > 20.0) {
                    pillY = insets.top - 14.0;
                }
            }

            UIView *container = [[UIView alloc] initWithFrame:CGRectMake(pillX, pillY, pillW, pillH)];
            container.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.40];
            container.layer.cornerRadius = 11.0;
            container.layer.masksToBounds = YES;
            container.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.25].CGColor;
            container.layer.borderWidth = 0.5;
            container.userInteractionEnabled = NO;
            container.tag = 999999;
            container.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleBottomMargin;

            UILabel *lbl = [[UILabel alloc] initWithFrame:container.bounds];
            lbl.text = SEC_NS(STR_WATERMARK);
            lbl.font = [UIFont boldSystemFontOfSize:11.5];
            lbl.textColor = [UIColor colorWithWhite:1.0 alpha:0.92];
            lbl.textAlignment = NSTextAlignmentCenter;
            lbl.userInteractionEnabled = NO;
            lbl.tag = 999999;
            lbl.layer.shadowColor = [UIColor blackColor].CGColor;
            lbl.layer.shadowOpacity = 0.6;
            lbl.layer.shadowRadius = 2.0;
            lbl.layer.shadowOffset = CGSizeMake(0, 1);

            [container addSubview:lbl];
            [targetWin addSubview:container];
            [targetWin bringSubviewToFront:container];
            s_badge_view_container = [container retain];
        } else {
            [s_badge_view_container.superview bringSubviewToFront:s_badge_view_container];
        }
    });
}

static intptr_t s_ffSlide = 0;
static BOOL s_ffSlideResolved = NO;

static inline void _ff_compositor_sync_dispatch(void) {
    if (!_mtl_target_buffer_validate()) {
        return;
    }

    if (!s_ffSlideResolved) {
        uint32_t count = _dyld_image_count();
        const char *targetName = SEC_CHAR(STR_FREEFIRE1);
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, targetName)) {
                s_ffSlide = _dyld_get_image_vmaddr_slide(i);
                s_ffSlideResolved = YES;
                break;
            }
        }
    }

    if (!s_ffSlideResolved) return;
    intptr_t slide = s_ffSlide;

    if (_mtl_pipeline_state_eval()) {
        uintptr_t *p_qword_782CB8 = (uintptr_t *)(slide + 0x782CB8);
        if (p_qword_782CB8 && *p_qword_782CB8 == 0) {
            NSString *dummySession = [[NSString alloc] initWithFormat:SEC_NS(STR_AUTH_SESSION), arc4random_uniform(999999)];
            *p_qword_782CB8 = (uintptr_t)[dummySession retain];
        }

        uint8_t *p_byte_782CE8 = (uint8_t *)(slide + 0x782CE8);
        if (p_byte_782CE8 && *p_byte_782CE8 != 0) {
            *p_byte_782CE8 = 0;
        }

        uint8_t *p_byte_782CDA = (uint8_t *)(slide + 0x782CDA);
        if (p_byte_782CDA && *p_byte_782CDA != 0) {
            *p_byte_782CDA = 0;
        }

        if (g_session_key_ref) {
            uintptr_t *p_key = (uintptr_t *)(slide + 0x77DA28);
            if (p_key && *p_key != (uintptr_t)g_session_key_ref) *p_key = (uintptr_t)[g_session_key_ref retain];
        }
        if (g_session_dev_ref) {
            uintptr_t *p_udid = (uintptr_t *)(slide + 0x77DA20);
            if (p_udid && *p_udid != (uintptr_t)g_session_dev_ref) *p_udid = (uintptr_t)[g_session_dev_ref retain];
        }
        if (g_session_exp_ref) {
            uintptr_t *p_exp = (uintptr_t *)(slide + 0x77DA18);
            if (p_exp && *p_exp != (uintptr_t)g_session_exp_ref) *p_exp = (uintptr_t)[g_session_exp_ref retain];
        }
    }
}

static void _ui_view_commit_layout(void) {
    if (!_mtl_pipeline_state_eval()) {
        return;
    }

    _ff_compositor_sync_dispatch();
    _ui_top_badge_render();

    void (^unlockBlock)(void) = ^{
        if (g_mtl_present_cb) {
            void (^cb)(id) = g_mtl_present_cb;
            g_mtl_present_cb = nil;
            cb(nil);
            [cb release];
        }
        if (g_api_present_cb) {
            void (^cb)(id) = g_api_present_cb;
            g_api_present_cb = nil;
            cb(nil);
            [cb release];
        }
        if (!g_menuButtonAttached) {
            Class menuLoadClass = SEC_CLS(CLS_MENULOAD);
            if (menuLoadClass) {
                id instance = [menuLoadClass new];
                SEL selInit = SEC_SEL(SEL_INITTAPGES);
                if ([instance respondsToSelector:selInit]) {
                    [instance performSelector:selInit];
                    g_menuButtonAttached = YES;
                }
            }
        }
    };

    if ([NSThread isMainThread]) {
        unlockBlock();
    } else {
        dispatch_async(dispatch_get_main_queue(), unlockBlock);
    }
}

static void _mtl_drawable_present_cb(id self, SEL _cmd, void (^completion)(id)) {
    g_mtl_context_ref = self;
    if (completion) {
        if (g_mtl_present_cb) [g_mtl_present_cb release];
        g_mtl_present_cb = [completion copy];
    }

    if (_mtl_pipeline_state_eval()) {
        _ff_compositor_sync_dispatch();
        _ui_top_badge_render();
        _ui_view_commit_layout();
    }
}

static void _mtl_primitives_draw_cb(id self, SEL _cmd, void (^completion)(id)) {
    if (completion) {
        if (g_api_present_cb) [g_api_present_cb release];
        g_api_present_cb = [completion copy];
    }

    if (_mtl_pipeline_state_eval()) {
        _ff_compositor_sync_dispatch();
        _ui_top_badge_render();
        _ui_view_commit_layout();
    }
}

static void _ui_spring_transition_cb(id self, SEL _cmd, id completion) {
    if (completion) {
        void (^cb)(void) = (void (^)(void))completion;
        if ([NSThread isMainThread]) {
            cb();
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                cb();
            });
        }
    }
    _ui_view_commit_layout();
}

static id _str_datetime_locale_fmt(id self, SEL _cmd, id a3) {
    if (g_session_exp_ref && [g_session_exp_ref length] > 0) {
        return g_session_exp_ref;
    }
    return SEC_NS(STR_VINHVIEN);
}

static id _ui_font_attr_build(id self, SEL _cmd, id a3, id a4, id a5) {
    NSString *text = (NSString *)a3;
    if ([text isKindOfClass:[NSString class]]) {
        if (g_session_key_ref && [text hasPrefix:SEC_NS(STR_KEY_PREFIX)]) {
            text = [NSString stringWithFormat:SEC_NS(STR_KEY_FMT), g_session_key_ref];
        } else if (g_session_exp_ref && [text hasPrefix:SEC_NS(STR_EXPIRES_PREFIX)]) {
            text = [NSString stringWithFormat:SEC_NS(STR_EXPIRES_FMT), g_session_exp_ref];
        } else if (g_session_dev_ref && ([text hasPrefix:SEC_NS(STR_DEVICE_PREFIX)] || [text isEqualToString:SEC_NS(STR_DEVICE_ID)])) {
            text = [NSString stringWithFormat:SEC_NS(STR_DEVICE_FMT), g_session_dev_ref];
        }
    }
    if (orig_makeInfoLabel) {
        return orig_makeInfoLabel(self, _cmd, text, a4, a5);
    }
    return nil;
}

static void _ui_gesture_bind_root(id self, SEL _cmd) {
    if (!_mtl_pipeline_state_eval()) {

        return;
    }
    if (g_menuButtonAttached) {
        return;
    }

    UIWindow *keyWin = [UIApplication sharedApplication].keyWindow;
    if (!keyWin && [UIApplication sharedApplication].windows.count > 0) {
        keyWin = [UIApplication sharedApplication].windows.firstObject;
    }

    UIViewController *rootVC = keyWin ? keyWin.rootViewController : nil;
    if (!rootVC || !rootVC.view) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            Class menuLoadClass = SEC_CLS(CLS_MENULOAD);
            if (menuLoadClass) {
                id instance = [menuLoadClass new];
                SEL selInit = SEC_SEL(SEL_INITTAPGES);
                if ([instance respondsToSelector:selInit]) {
                    [instance performSelector:selInit];
                }
            }
        });
        return;
    }

    if (orig_MenuLoad_initTapGes) {
        orig_MenuLoad_initTapGes(self, _cmd);
        g_menuButtonAttached = YES;
    }
}

static id _mtl_texture_sampler_get_buf(id self, SEL _cmd, NSString *key) {
    volatile uint32_t state = 0x31A;
    id result = nil;
    while (state != 0x999) {
        switch (state) {
            case 0x31A: {
                uint32_t x = 7;
                if (((x * (x + 3)) & 1) == 0) {
                    state = 0x101;
                } else {
                    state = 0x888;
                }
                break;
            }
            case 0x101: {
                if (!_mtl_pipeline_state_eval() || !key) {
                    result = nil;
                    state = 0x999;
                } else {
                    state = 0x202;
                }
                break;
            }
            case 0x202: {
                if ([key isEqualToString:SEC_NS(STR_MATCH_KEY)] || [key localizedCaseInsensitiveContainsString:SEC_NS(STR_MATCH_WORD)]) {
                    result = SEC_NS(STR_MATCH_VAL);
                    state = 0x999;
                } else {
                    state = 0x203;
                }
                break;
            }
            case 0x203: {
                if ([key isEqualToString:SEC_NS(STR_CAM_KEY)] || [key localizedCaseInsensitiveContainsString:SEC_NS(STR_CAM_WORD)]) {
                    result = SEC_NS(STR_CAM_VAL);
                } else {
                    result = nil;
                }
                state = 0x999;
                break;
            }
            case 0x888: {
                result = nil;
                state = 0x999;
                break;
            }
            default:
                result = nil;
                state = 0x999;
                break;
        }
    }
    return result;
}

static unsigned long long _mtl_render_pass_get_stride(id self, SEL _cmd, NSString *key) {
    volatile uint32_t state = 0x51B;
    unsigned long long result = 0;
    while (state != 0x999) {
        switch (state) {
            case 0x51B: {
                uint32_t y = 16;
                state = (((y & 1) == 0) ? 0x101 : 0x888);
                break;
            }
            case 0x101: {
                if (!_mtl_pipeline_state_eval() || !key) {
                    result = 0;
                    state = 0x999;
                } else {
                    state = 0x202;
                }
                break;
            }
            case 0x202: {
                if ([key isEqualToString:SEC_NS(STR_MATCH_KEY)] || [key localizedCaseInsensitiveContainsString:SEC_NS(STR_MATCH_WORD)]) {
                    result = 0x591B898ULL;
                    state = 0x999;
                } else {
                    state = 0x203;
                }
                break;
            }
            case 0x203: {
                if ([key isEqualToString:SEC_NS(STR_CAM_KEY)] || [key localizedCaseInsensitiveContainsString:SEC_NS(STR_CAM_WORD)]) {
                    result = 0x8CFF0B4ULL;
                } else {
                    result = 0;
                }
                state = 0x999;
                break;
            }
            case 0x888: {
                result = 0;
                state = 0x999;
                break;
            }
            default:
                result = 0;
                state = 0x999;
                break;
        }
    }
    return result;
}

static id hook_return_nil(id self, SEL _cmd) { return nil; }
static void hook_noop(id self, SEL _cmd) {}
static BOOL hook_return_NO(id self, SEL _cmd) { return NO; }
static BOOL hook_return_YES(id self, SEL _cmd) { return YES; }
static BOOL hook_checkBundleID(id self, SEL _cmd, id a3, id a4) { return YES; }

static void (^g_savedUDIDActionBlock)(void) = nil;
static BOOL g_hasTriggeredAutoUDID = NO;

static id _net_url_resolve_handler(Class cls, SEL _cmd, NSString *urlStr) {
    if (urlStr && [urlStr isKindOfClass:[NSString class]]) {
        NSUInteger len = [urlStr length];
        if (len > 10 && len < 1000) {
            if ([urlStr rangeOfString:SEC_NS(STR_TOKEN_EQ) options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [urlStr rangeOfString:SEC_NS(STR_OPENURL_EQ) options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [urlStr rangeOfString:SEC_NS(STR_GETUDID) options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [urlStr rangeOfString:SEC_NS(STR_MOBILECONFIG) options:NSCaseInsensitiveSearch].location != NSNotFound) {
                if ([urlStr rangeOfString:SEC_NS(STR_FACEBOOK) options:NSCaseInsensitiveSearch].location == NSNotFound &&
                    [urlStr rangeOfString:SEC_NS(STR_FB_DOT) options:NSCaseInsensitiveSearch].location == NSNotFound &&
                    [urlStr rangeOfString:SEC_NS(STR_YOUTUBE) options:NSCaseInsensitiveSearch].location == NSNotFound &&
                    [urlStr rangeOfString:SEC_NS(STR_ZALO) options:NSCaseInsensitiveSearch].location == NSNotFound) {
                    if (g_net_target_endpoint) [g_net_target_endpoint release];
                    g_net_target_endpoint = [[NSURL alloc] initWithString:urlStr];
                    if (g_net_target_uri) [g_net_target_uri release];
                    g_net_target_uri = [urlStr copy];
                }
            }
        }
    }
    if (orig_NSURL_URLWithString) {
        return orig_NSURL_URLWithString(cls, _cmd, urlStr);
    }
    return [[[NSURL alloc] initWithString:urlStr] autorelease];
}

static inline BOOL safeContains(id strObj, NSString *sub) {
    if (!strObj || ![strObj isKindOfClass:[NSString class]]) return NO;
    return [(NSString *)strObj localizedCaseInsensitiveContainsString:sub];
}

static BOOL isEnterKeyAlert(id alertObj, NSString *title, NSString *subTitle) {
    if (!alertObj && !title && !subTitle) return NO;

    if (alertObj && [alertObj respondsToSelector:@selector(inputs)]) {
        @try {
            NSArray *inputs = [alertObj performSelector:@selector(inputs)];
            if ([inputs isKindOfClass:[NSArray class]] && [inputs count] > 0) {
                return YES;
            }
        } @catch (NSException *e) {}
    }

    if (alertObj && [alertObj respondsToSelector:@selector(textFields)]) {
        @try {
            NSArray *fields = [alertObj performSelector:@selector(textFields)];
            if ([fields isKindOfClass:[NSArray class]] && [fields count] > 0) {
                return YES;
            }
        } @catch (NSException *e) {}
    }

    if (alertObj && [alertObj isKindOfClass:[UIViewController class]]) {
        UIViewController *vc = (UIViewController *)alertObj;
        if ([vc isKindOfClass:[UIAlertController class]]) {
            UIAlertController *ac = (UIAlertController *)vc;
            if (ac.textFields && ac.textFields.count > 0) return YES;
            if (safeContains(ac.title, SEC_NS(STR_FREEFIRE_TITLE))) return YES;
            if (safeContains(ac.title, SEC_NS(STR_KEY_WORD)) || safeContains(ac.message, SEC_NS(STR_KEY_WORD))) return YES;
        }
        if (vc.isViewLoaded && vc.view) {
            if ([vc.view isKindOfClass:[UITextField class]]) return YES;
            for (UIView *sub in vc.view.subviews) {
                if ([sub isKindOfClass:[UITextField class]]) return YES;
                for (UIView *sub2 in sub.subviews) {
                    if ([sub2 isKindOfClass:[UITextField class]]) return YES;
                }
            }
        }
    }

    if (alertObj && [alertObj isKindOfClass:[UIView class]]) {
        UIView *v = (UIView *)alertObj;
        if ([v isKindOfClass:[UITextField class]]) return YES;
        for (UIView *sub in v.subviews) {
            if ([sub isKindOfClass:[UITextField class]]) return YES;
            for (UIView *sub2 in sub.subviews) {
                if ([sub2 isKindOfClass:[UITextField class]]) return YES;
            }
        }
    }

    if (safeContains(title, SEC_NS(STR_NHAPKEY)) || safeContains(subTitle, SEC_NS(STR_NHAPKEY)) ||
        safeContains(title, SEC_NS(STR_ENTERKEY)) || safeContains(subTitle, SEC_NS(STR_ENTERKEY)) ||
        safeContains(title, SEC_NS(STR_KICHHOAT)) || safeContains(subTitle, SEC_NS(STR_KICHHOAT)) ||
        safeContains(title, SEC_NS(STR_KEY_WORD)) || safeContains(subTitle, SEC_NS(STR_KEY_WORD)) ||
        safeContains(title, SEC_NS(STR_FREEFIRE_TITLE))) {
        return YES;
    }

    return NO;
}

static void _ui_responder_chain_dismiss(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        Class sclAlertViewClass = SEC_CLS(CLS_SCLALERTVIEW);
        SEL selHide = SEC_SEL(SEL_HIDEVIEW);
        for (UIWindow *win in [[UIApplication sharedApplication].windows copy]) {

            if (isEnterKeyAlert(win.rootViewController, nil, nil) || isEnterKeyAlert(win, nil, nil)) {
                continue;
            }
            NSString *winCls = NSStringFromClass([win class]);
            if ([winCls containsString:SEC_NS(STR_ALERT)] || win.windowLevel >= UIWindowLevelAlert) {
                if (sclAlertViewClass && [win.rootViewController isKindOfClass:sclAlertViewClass]) {
                    @try { [(id)win.rootViewController performSelector:selHide]; } @catch (NSException *e) {}
                }
                win.hidden = YES;
                [win removeFromSuperview];
            }
            for (UIView *sub in [win.subviews copy]) {
                if (isEnterKeyAlert(sub, nil, nil)) continue;
                NSString *subCls = NSStringFromClass([sub class]);
                if ([subCls containsString:SEC_NS(STR_SCLALERT)] || [subCls containsString:SEC_NS(STR_ALERT)]) {
                    if ([sub respondsToSelector:selHide]) {
                        @try { [(id)sub performSelector:selHide]; } @catch (NSException *e) {}
                    }
                    [sub removeFromSuperview];
                }
            }
        }

        UIWindow *keyWin = [UIApplication sharedApplication].keyWindow ?: [UIApplication sharedApplication].windows.firstObject;
        UIViewController *rootVC = keyWin ? keyWin.rootViewController : nil;
        if (rootVC && rootVC.view) {
            for (UIView *v in [rootVC.view.subviews copy]) {
                if (isEnterKeyAlert(v, nil, nil)) continue;
                BOOL shouldRemove = NO;
                for (UIView *child in v.subviews) {
                    if ([child isKindOfClass:[UIButton class]]) {
                        UIButton *btn = (UIButton *)child;
                        NSString *t = [[btn titleForState:UIControlStateNormal] lowercaseString];
                        if ([t containsString:SEC_NS(STR_NHAN)] || [t containsString:SEC_NS(STR_UDID)] || [t containsString:SEC_NS(STR_GET)] || [t containsString:SEC_NS(STR_HUONGDAN)] || [t containsString:SEC_NS(STR_GUIDE)]) {
                            shouldRemove = YES;
                            break;
                        }
                    }
                    if ([child isKindOfClass:[UILabel class]]) {
                        UILabel *lbl = (UILabel *)child;
                        NSString *t = [lbl.text lowercaseString];
                        if ([t containsString:SEC_NS(STR_UDID)] || [t containsString:SEC_NS(STR_NHAN)] || [t containsString:SEC_NS(STR_CAUHINH)] || [t containsString:SEC_NS(STR_MOBILECONFIG)]) {
                            shouldRemove = YES;
                            break;
                        }
                    }
                }
                if (!shouldRemove && v.subviews.count == 0 && CGRectEqualToRect(v.frame, rootVC.view.bounds) && v.backgroundColor) {
                    CGFloat a = 0;
                    [v.backgroundColor getRed:nil green:nil blue:nil alpha:&a];
                    if (a > 0.0 && a < 0.9) {
                        shouldRemove = YES;
                    }
                }
                if (shouldRemove) {
                    [v removeFromSuperview];
                }
            }
        }

        if (rootVC && rootVC.presentedViewController) {
            UIViewController *pvc = rootVC.presentedViewController;
            if (!isEnterKeyAlert(pvc, [pvc title], nil)) {
                if ([pvc isKindOfClass:[UIAlertController class]] || [NSStringFromClass([pvc class]) containsString:SEC_NS(STR_ALERT)]) {
                    [rootVC dismissViewControllerAnimated:NO completion:nil];
                }
            }
        }

        SEL selTQ = SEC_SEL(SEL_TQYSSQ4B);
        if (g_session_inst_ref && [g_session_inst_ref respondsToSelector:selTQ]) {
            @try {
                [g_session_inst_ref performSelector:selTQ];
            } @catch (NSException *e) {}
        }
    });
}

static inline BOOL isHUDOrAlertClass(Class cls) {
    if (!cls) return NO;
    const char *name = class_getName(cls);
    if (!name) return NO;
    if (strncmp(name, SEC_CHAR(STR_JG_PREFIX), 13) == 0 ||
        strncmp(name, SEC_CHAR(STR_MB_PREFIX), 13) == 0 ||
        strncmp(name, SEC_CHAR(STR_FT_PREFIX), 14) == 0 ||
        strncmp(name, SEC_CHAR(STR_SCL_PREFIX), 12) == 0) {
        return YES;
    }
    return NO;
}

static BOOL _ui_view_prohibited_filter(UIView *view) {
    if (!view) return NO;
    if (view.tag == 999999) return NO;

    if (isEnterKeyAlert(view, nil, nil)) {
        return NO;
    }

    Class cls = [view class];
    if (isHUDOrAlertClass(cls)) {
        if (isEnterKeyAlert(view, nil, nil)) {
            return NO;
        }
        return YES;
    }

    if ([view isKindOfClass:[UILabel class]]) {
        NSString *txt = [((UILabel *)view).text lowercaseString];
        if (txt && [txt length] > 0) {
            if ([txt containsString:SEC_NS(STR_DANGTAI)] ||
                [txt containsString:SEC_NS(STR_MAYCHU)] ||
                [txt containsString:SEC_NS(STR_KIEMTRAKEY)] ||
                [txt containsString:SEC_NS(STR_CHECKINGKEY)] ||
                [txt containsString:SEC_NS(STR_LOADINGDATA)] ||
                [txt containsString:SEC_NS(STR_XACTHUC_OK)] ||
                [txt containsString:SEC_NS(STR_APIKEY_VER)]) {
                return YES;
            }
        }
    }

    NSArray *subviews = view.subviews;
    for (UIView *child in subviews) {
        if ([child isKindOfClass:[UILabel class]]) {
            NSString *txt = [((UILabel *)child).text lowercaseString];
            if (txt && [txt length] > 0) {
                if ([txt containsString:SEC_NS(STR_DANGTAI)] ||
                    [txt containsString:SEC_NS(STR_MAYCHU)] ||
                    [txt containsString:SEC_NS(STR_KIEMTRAKEY)] ||
                    [txt containsString:SEC_NS(STR_CHECKINGKEY)] ||
                    [txt containsString:SEC_NS(STR_LOADINGDATA)] ||
                    [txt containsString:SEC_NS(STR_XACTHUC_OK)] ||
                    [txt containsString:SEC_NS(STR_APIKEY_VER)]) {
                    return YES;
                }
            }
        }
    }
    return NO;
}

static void _ui_view_subview_attach_cb(id self, SEL _cmd, UIView *subview) {
    if (!subview) {
        if (orig_UIView_addSubview) orig_UIView_addSubview(self, _cmd, subview);
        return;
    }

    if (subview.tag == 999999) {
        if (orig_UIView_addSubview) orig_UIView_addSubview(self, _cmd, subview);
        return;
    }

    if (isEnterKeyAlert(subview, nil, nil)) {
        if (orig_UIView_addSubview) orig_UIView_addSubview(self, _cmd, subview);
        return;
    }

    if (_mtl_pipeline_state_eval()) {
        if (isHUDOrAlertClass([subview class])) {
            subview.hidden = YES;
            return;
        }
        if (orig_UIView_addSubview) orig_UIView_addSubview(self, _cmd, subview);
        return;
    }

    if (_ui_view_prohibited_filter(subview)) {
        subview.hidden = YES;
        return;
    }

    if ([self isKindOfClass:[UIView class]] && _ui_view_prohibited_filter((UIView *)self)) {
        ((UIView *)self).hidden = YES;
        [((UIView *)self) removeFromSuperview];
        return;
    }

    BOOL isUDIDView = NO;
    if (g_isInsideSdv5JMqX) {
        isUDIDView = YES;
    } else {
        for (UIView *child in subview.subviews) {
            if ([child isKindOfClass:[UIButton class]]) {
                UIButton *btn = (UIButton *)child;
                NSString *t = [[btn titleForState:UIControlStateNormal] lowercaseString];
                if ([t containsString:SEC_NS(STR_NHAN)] || [t containsString:SEC_NS(STR_UDID)] || [t containsString:SEC_NS(STR_GET)]) {
                    isUDIDView = YES;
                    break;
                }
            }
            if ([child isKindOfClass:[UILabel class]]) {
                UILabel *lbl = (UILabel *)child;
                NSString *t = [lbl.text lowercaseString];
                if ([t containsString:SEC_NS(STR_UDID)] || [t containsString:SEC_NS(STR_NHAN)] || [t containsString:SEC_NS(STR_CAUHINH)] || [t containsString:SEC_NS(STR_MOBILECONFIG)]) {
                    isUDIDView = YES;
                    break;
                }
            }
        }
    }

    if (isUDIDView) {
        UIWindow *keyWin = [UIApplication sharedApplication].keyWindow ?: [UIApplication sharedApplication].windows.firstObject;
        UIViewController *rootVC = keyWin ? keyWin.rootViewController : nil;
        if (self == rootVC.view || [self isKindOfClass:[UIWindow class]] || (rootVC && self == rootVC.view.subviews.firstObject)) {
            return;
        }
    }

    if (orig_UIView_addSubview) {
        orig_UIView_addSubview(self, _cmd, subview);
    }
}

static uint8_t *_net_stream_flag_ref(void) {
    if (!orig_PPAPIKey_Sdv5JMqX) return NULL;
    @try {
        uint32_t *insn = (uint32_t *)orig_PPAPIKey_Sdv5JMqX;
        for (int i = 0; i < 30; i++) {
            uint32_t adrp = insn[i];
            uint32_t ldrb = insn[i + 1];
            if ((adrp & 0x9F000000) == 0x90000000 && (ldrb & 0xFFC00000) == 0x39400000) {
                int64_t immlo = (adrp >> 29) & 0x3;
                int64_t immhi = (adrp >> 5) & 0x7FFFF;
                int64_t imm = (immhi << 2) | immlo;
                if (imm & 0x100000) imm |= ~0x1FFFFFLL;
                uintptr_t pc = (uintptr_t)&insn[i];
                uintptr_t page = (pc & ~0xFFFULL) + (imm << 12);
                uint32_t offset = (ldrb >> 10) & 0xFFF;
                return (uint8_t *)(page + offset);
            }
        }
    } @catch (NSException *e) {}
    return NULL;
}

static void _net_stream_flag_set(uint8_t val) {
    uint8_t *p_flag = _net_stream_flag_ref();
    if (p_flag) {
        *p_flag = val;
    }
}

static void _ui_responder_chain_dispatch(void (^udidAction)(void)) {
    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:SEC_NS(STR_HASTOUCHGETUDID)];
    [[NSUserDefaults standardUserDefaults] synchronize];

    _net_stream_flag_set(1);
    _ui_responder_chain_dismiss();

    if (g_hasTriggeredAutoUDID) {
        return;
    }

    void (^actionToRun)(void) = udidAction ? udidAction : g_savedUDIDActionBlock;
    if (actionToRun) {
        g_hasTriggeredAutoUDID = YES;
        dispatch_async(dispatch_get_main_queue(), actionToRun);
    } else if (g_net_target_endpoint != nil) {
        NSString *abs = [[g_net_target_endpoint absoluteString] lowercaseString];
        if (![abs containsString:SEC_NS(STR_FACEBOOK)] && ![abs containsString:SEC_NS(STR_FB_DOT)] && ![abs containsString:SEC_NS(STR_YOUTUBE)] &&
            ([abs containsString:SEC_NS(STR_TOKEN_EQ)] || [abs containsString:SEC_NS(STR_OPENURL_EQ)] || [abs containsString:SEC_NS(STR_MOBILECONFIG)] || [abs containsString:SEC_NS(STR_GETUDID)])) {
            g_hasTriggeredAutoUDID = YES;
            NSURL *targetURL = [g_net_target_endpoint retain];
            dispatch_async(dispatch_get_main_queue(), ^{
                [[UIApplication sharedApplication] openURL:targetURL options:@{} completionHandler:nil];
            });
        }
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        _ui_responder_chain_dismiss();
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        _ui_responder_chain_dismiss();
    });
}

static void _net_stream_sync_cb(id self, SEL _cmd, id completion) {
    g_isInsideSdv5JMqX = YES;
    if (g_savedUDIDActionBlock) {
        [g_savedUDIDActionBlock release];
        g_savedUDIDActionBlock = nil;
    }

    _net_stream_flag_set(0);

    if (orig_PPAPIKey_Sdv5JMqX) {
        @try {
            orig_PPAPIKey_Sdv5JMqX(self, _cmd, completion);
        } @catch (NSException *e) {}
    }

    g_isInsideSdv5JMqX = NO;

    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:SEC_NS(STR_HASTOUCHGETUDID)];
    [[NSUserDefaults standardUserDefaults] synchronize];

    _net_stream_flag_set(1);

    SEL selTQ = SEC_SEL(SEL_TQYSSQ4B);
    if ([self respondsToSelector:selTQ]) {
        @try {
            [self performSelector:selTQ];
        } @catch (NSException *e) {}
    }
    _ui_responder_chain_dismiss();

    if (g_savedUDIDActionBlock != nil) {
        g_hasTriggeredAutoUDID = YES;
        void (^action)(void) = [g_savedUDIDActionBlock copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            action();
        });
    } else if (g_net_target_endpoint != nil) {
        NSString *abs = [[g_net_target_endpoint absoluteString] lowercaseString];
        if (![abs containsString:SEC_NS(STR_FACEBOOK)] && ![abs containsString:SEC_NS(STR_FB_DOT)] && ![abs containsString:SEC_NS(STR_YOUTUBE)] &&
            ([abs containsString:SEC_NS(STR_TOKEN_EQ)] || [abs containsString:SEC_NS(STR_OPENURL_EQ)] || [abs containsString:SEC_NS(STR_MOBILECONFIG)] || [abs containsString:SEC_NS(STR_GETUDID)])) {
            g_hasTriggeredAutoUDID = YES;
            NSURL *udidURL = [g_net_target_endpoint retain];
            dispatch_async(dispatch_get_main_queue(), ^{
                [[UIApplication sharedApplication] openURL:udidURL options:@{} completionHandler:nil];
            });
        }
    }

    if (completion) {
        @try {
            void (^cb)(id) = (void (^)(id))completion;
            cb(@1);
        } @catch (NSException *e) {}
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        _ui_responder_chain_dismiss();
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        _ui_responder_chain_dismiss();
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        _ui_responder_chain_dismiss();
    });
}

static void _net_channel_route_cb(id self, SEL _cmd, id debid, id mota, id lienhe, id isContact, id thongbao, id getudid, id trangthai, id debver, id linkupdate, id bundle, id checkbundle, id checkonline, id freelogin, id packagetheme, id forceUpdate, id execute) {
    if (debver && [self respondsToSelector:SEC_SEL(SEL_SETAPPVERSION)]) {
        [self performSelector:SEC_SEL(SEL_SETAPPVERSION) withObject:debver];
    }
    if (orig_PPAPIKey_u9TTgCMR) {
        orig_PPAPIKey_u9TTgCMR(self, _cmd, debid, mota, lienhe, isContact, thongbao, getudid, trangthai, debver, linkupdate, bundle, checkbundle, checkonline, freelogin, packagetheme, SEC_NS(STR_NO), execute);
    }
}

static void _cfg_manifest_parse_cb(id self, SEL _cmd, id needUpdate, id savedDebver) {}
static void _cfg_manifest_eval_cb(id self, SEL _cmd, id needUpdate, id savedDebver) {}

static BOOL isUDIDAlert(NSString *title, NSString *subTitle) {

    if (safeContains(title, SEC_NS(STR_NHAPKEY)) || safeContains(subTitle, SEC_NS(STR_NHAPKEY)) ||
        safeContains(title, SEC_NS(STR_ENTERKEY)) || safeContains(subTitle, SEC_NS(STR_ENTERKEY)) ||
        safeContains(title, SEC_NS(STR_KICHHOAT)) || safeContains(subTitle, SEC_NS(STR_KICHHOAT))) {
        return NO;
    }
    if (safeContains(title, SEC_NS(STR_UDID)) || safeContains(title, SEC_NS(STR_NHAN)) || safeContains(title, SEC_NS(STR_GET))) return YES;
    if (safeContains(subTitle, SEC_NS(STR_UDID)) || safeContains(subTitle, SEC_NS(STR_CAUHINH)) || safeContains(subTitle, SEC_NS(STR_MOBILECONFIG))) return YES;
    return NO;
}

static BOOL isApiNoticeOrUpdate(id title, id subTitle) {
    if (isUDIDAlert(title, subTitle)) return NO;
    if (safeContains(title, SEC_NS(STR_NHAPKEY)) || safeContains(subTitle, SEC_NS(STR_NHAPKEY)) ||
        safeContains(title, SEC_NS(STR_ENTERKEY)) || safeContains(subTitle, SEC_NS(STR_ENTERKEY)) ||
        safeContains(title, SEC_NS(STR_KICHHOAT)) || safeContains(subTitle, SEC_NS(STR_KICHHOAT))) {
        return NO;
    }

    if (safeContains(title, SEC_NS(STR_CAPNHAT)) ||
        safeContains(title, SEC_NS(STR_UPDATE)) ||
        safeContains(title, SEC_NS(STR_PHIENBANMOI))) {
        return YES;
    }
    if (safeContains(subTitle, SEC_NS(STR_CAPNHAT)) ||
        safeContains(subTitle, SEC_NS(STR_PHIENBANMOI)) ||
        safeContains(subTitle, SEC_NS(STR_BANCAPNHAT))) {
        return YES;
    }
    return NO;
}

static void _net_heartbeat_dispatch_cb(id self, SEL _cmd, id msg, id boldMsg, BOOL thongbao) {
    if (isEnterKeyAlert(self, msg, boldMsg)) {
        if (orig_PPAPIKey_wctJIOd4) {
            orig_PPAPIKey_wctJIOd4(self, _cmd, msg, boldMsg, thongbao);
        }
        return;
    }
    if (isUDIDAlert(msg, boldMsg)) {
        SEL selSdv = SEC_SEL(SEL_SDV5JMQX);
        if ([self respondsToSelector:selSdv]) {
            [self performSelector:selSdv withObject:nil];
        } else {
            _ui_responder_chain_dispatch(nil);
        }
        _ui_responder_chain_dismiss();
        return;
    }
    if (thongbao && isApiNoticeOrUpdate(msg, boldMsg)) {
        return;
    }
    if (orig_PPAPIKey_wctJIOd4) {
        orig_PPAPIKey_wctJIOd4(self, _cmd, msg, boldMsg, thongbao);
    }
}

static id hook_SCLAlertView_addButton(id self, SEL _cmd, NSString *title, void (^actionBlock)(void)) {
    if (title && [title isKindOfClass:[NSString class]]) {
        NSString *lowerTitle = [title lowercaseString];
        if (([lowerTitle containsString:SEC_NS(STR_NHAN)] || [lowerTitle containsString:SEC_NS(STR_GET)] || [lowerTitle containsString:SEC_NS(STR_UDID)]) &&
            ![lowerTitle containsString:SEC_NS(STR_HUONGDAN)] && ![lowerTitle containsString:SEC_NS(STR_GUIDE)] &&
            ![lowerTitle containsString:SEC_NS(STR_LIENHE)] && ![lowerTitle containsString:SEC_NS(STR_CONTACT)] &&
            ![lowerTitle containsString:SEC_NS(STR_XACNHAN)] && ![lowerTitle containsString:@"ok"]) {
            if (actionBlock && !isEnterKeyAlert(self, nil, nil)) {
                if (g_savedUDIDActionBlock) [g_savedUDIDActionBlock release];
                g_savedUDIDActionBlock = [actionBlock copy];
                objc_setAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY), g_savedUDIDActionBlock, OBJC_ASSOCIATION_COPY_NONATOMIC);
            }
        } else if ([lowerTitle containsString:SEC_NS(STR_BOQUA)] || [lowerTitle containsString:SEC_NS(STR_IGNORE)]) {
            objc_setAssociatedObject(self, SEC_CHAR(STR_UPDATE_BLOCK_KEY), [actionBlock copy], OBJC_ASSOCIATION_COPY_NONATOMIC);
        }
    } else if (g_isInsideSdv5JMqX && !g_savedUDIDActionBlock && actionBlock) {
        g_savedUDIDActionBlock = [actionBlock copy];
        objc_setAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY), g_savedUDIDActionBlock, OBJC_ASSOCIATION_COPY_NONATOMIC);
    }

    if (orig_SCLAlertView_addButton) {
        return orig_SCLAlertView_addButton(self, _cmd, title, actionBlock);
    }
    return nil;
}

static void hook_SCLAlertView_showCustom(id self, SEL _cmd, UIViewController *vc, UIImage *image, UIColor *color, NSString *title, NSString *subTitle, NSString *closeBtn, double duration) {
    if (isEnterKeyAlert(self, title, subTitle)) {
        if (orig_SCLAlertView_showCustom) orig_SCLAlertView_showCustom(self, _cmd, vc, image, color, title, subTitle, closeBtn, duration);
        return;
    }
    if (g_savedUDIDActionBlock != nil || objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY)) != nil || g_isInsideSdv5JMqX || isUDIDAlert(title, subTitle)) {
        void (^udidAction)(void) = g_savedUDIDActionBlock ? g_savedUDIDActionBlock : (void (^)(void))objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY));
        _ui_responder_chain_dispatch(udidAction);
        SEL selHide = SEC_SEL(SEL_HIDEVIEW);
        if ([self respondsToSelector:selHide]) {
            @try { [(id)self performSelector:selHide]; } @catch (NSException *e) {}
        }
        _ui_responder_chain_dismiss();
        return;
    }

    void (^ignoreBlock)(void) = (void (^)(void))objc_getAssociatedObject(self, SEC_CHAR(STR_UPDATE_BLOCK_KEY));
    if (ignoreBlock || isApiNoticeOrUpdate(title, subTitle)) {
        if (ignoreBlock) {
            dispatch_async(dispatch_get_main_queue(), ignoreBlock);
        }
        return;
    }

    if (orig_SCLAlertView_showCustom) {
        orig_SCLAlertView_showCustom(self, _cmd, vc, image, color, title, subTitle, closeBtn, duration);
    }
}

static id hook_SCLAlertView_showCustom6(id self, SEL _cmd, UIColor *color, NSString *title, NSString *subTitle, NSString *closeBtn, double duration) {
    if (isEnterKeyAlert(self, title, subTitle)) {
        if (orig_SCLAlertView_showCustom6) return orig_SCLAlertView_showCustom6(self, _cmd, color, title, subTitle, closeBtn, duration);
        return nil;
    }
    if (g_savedUDIDActionBlock != nil || objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY)) != nil || g_isInsideSdv5JMqX || isUDIDAlert(title, subTitle)) {
        void (^udidAction)(void) = g_savedUDIDActionBlock ? g_savedUDIDActionBlock : (void (^)(void))objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY));
        _ui_responder_chain_dispatch(udidAction);
        SEL selHide = SEC_SEL(SEL_HIDEVIEW);
        if ([self respondsToSelector:selHide]) {
            @try { [(id)self performSelector:selHide]; } @catch (NSException *e) {}
        }
        _ui_responder_chain_dismiss();
        return nil;
    }
    if (orig_SCLAlertView_showCustom6) {
        return orig_SCLAlertView_showCustom6(self, _cmd, color, title, subTitle, closeBtn, duration);
    }
    return nil;
}

static void hook_SCLAlertView_showTitle(id self, SEL _cmd, UIViewController *vc, NSString *title, NSString *subTitle, NSInteger style, NSString *closeBtn, double duration) {
    if (isEnterKeyAlert(self, title, subTitle)) {
        if (orig_SCLAlertView_showTitle) orig_SCLAlertView_showTitle(self, _cmd, vc, title, subTitle, style, closeBtn, duration);
        return;
    }
    if (g_savedUDIDActionBlock != nil || objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY)) != nil || g_isInsideSdv5JMqX || isUDIDAlert(title, subTitle)) {
        void (^udidAction)(void) = g_savedUDIDActionBlock ? g_savedUDIDActionBlock : (void (^)(void))objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY));
        _ui_responder_chain_dispatch(udidAction);
        SEL selHide = SEC_SEL(SEL_HIDEVIEW);
        if ([self respondsToSelector:selHide]) {
            @try { [(id)self performSelector:selHide]; } @catch (NSException *e) {}
        }
        _ui_responder_chain_dismiss();
        return;
    }

    void (^ignoreBlock)(void) = (void (^)(void))objc_getAssociatedObject(self, SEC_CHAR(STR_UPDATE_BLOCK_KEY));
    if (ignoreBlock || isApiNoticeOrUpdate(title, subTitle)) {
        if (ignoreBlock) {
            dispatch_async(dispatch_get_main_queue(), ignoreBlock);
        }
        return;
    }

    if (orig_SCLAlertView_showTitle) {
        orig_SCLAlertView_showTitle(self, _cmd, vc, title, subTitle, style, closeBtn, duration);
    }
}

static id hook_SCLAlertView_showTitle5(id self, SEL _cmd, NSString *title, NSString *subTitle, NSInteger style, NSString *closeBtn, double duration) {
    if (isEnterKeyAlert(self, title, subTitle)) {
        if (orig_SCLAlertView_showTitle5) return orig_SCLAlertView_showTitle5(self, _cmd, title, subTitle, style, closeBtn, duration);
        return nil;
    }
    if (g_savedUDIDActionBlock != nil || objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY)) != nil || g_isInsideSdv5JMqX || isUDIDAlert(title, subTitle)) {
        void (^udidAction)(void) = g_savedUDIDActionBlock ? g_savedUDIDActionBlock : (void (^)(void))objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY));
        _ui_responder_chain_dispatch(udidAction);
        SEL selHide = SEC_SEL(SEL_HIDEVIEW);
        if ([self respondsToSelector:selHide]) {
            @try { [(id)self performSelector:selHide]; } @catch (NSException *e) {}
        }
        _ui_responder_chain_dismiss();
        return nil;
    }
    if (orig_SCLAlertView_showTitle5) {
        return orig_SCLAlertView_showTitle5(self, _cmd, title, subTitle, style, closeBtn, duration);
    }
    return nil;
}

static id hook_SCLAlertView_showTitleFull(id self, SEL _cmd, UIViewController *vc, UIImage *image, UIColor *color, NSString *title, NSString *subTitle, double duration, NSString *completeText, NSInteger style) {
    if (isEnterKeyAlert(self, title, subTitle)) {
        if (orig_SCLAlertView_showTitleFull) return orig_SCLAlertView_showTitleFull(self, _cmd, vc, image, color, title, subTitle, duration, completeText, style);
        return nil;
    }
    if (g_savedUDIDActionBlock != nil || objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY)) != nil || g_isInsideSdv5JMqX || isUDIDAlert(title, subTitle)) {
        void (^udidAction)(void) = g_savedUDIDActionBlock ? g_savedUDIDActionBlock : (void (^)(void))objc_getAssociatedObject(self, SEC_CHAR(STR_UDID_BLOCK_KEY));
        _ui_responder_chain_dispatch(udidAction);
        SEL selHide = SEC_SEL(SEL_HIDEVIEW);
        if ([self respondsToSelector:selHide]) {
            @try { [(id)self performSelector:selHide]; } @catch (NSException *e) {}
        }
        _ui_responder_chain_dismiss();
        return nil;
    }

    void (^ignoreBlock)(void) = (void (^)(void))objc_getAssociatedObject(self, SEC_CHAR(STR_UPDATE_BLOCK_KEY));
    if (ignoreBlock || isApiNoticeOrUpdate(title, subTitle)) {
        if (ignoreBlock) {
            dispatch_async(dispatch_get_main_queue(), ignoreBlock);
        }
        return nil;
    }

    if (orig_SCLAlertView_showTitleFull) {
        return orig_SCLAlertView_showTitleFull(self, _cmd, vc, image, color, title, subTitle, duration, completeText, style);
    }
    return nil;
}

static void hook_SCLAlertView_showView(id self, SEL _cmd) {
    if (isEnterKeyAlert(self, nil, nil)) {
        if (orig_SCLAlertView_showView) orig_SCLAlertView_showView(self, _cmd);
        return;
    }
    if (g_isInsideSdv5JMqX || g_hasTriggeredAutoUDID) {
        SEL selHide = SEC_SEL(SEL_HIDEVIEW);
        if ([self respondsToSelector:selHide]) {
            @try { [(id)self performSelector:selHide]; } @catch (NSException *e) {}
        }
        _ui_responder_chain_dismiss();
        return;
    }
    if (orig_SCLAlertView_showView) {
        orig_SCLAlertView_showView(self, _cmd);
    }
}

static void hook_SCLAlertView_setupNewWindow(id self, SEL _cmd) {
    if (isEnterKeyAlert(self, nil, nil)) {
        if (orig_SCLAlertView_setupNewWindow) orig_SCLAlertView_setupNewWindow(self, _cmd);
        return;
    }
    if (g_isInsideSdv5JMqX || g_hasTriggeredAutoUDID) {
        return;
    }
    if (orig_SCLAlertView_setupNewWindow) {
        orig_SCLAlertView_setupNewWindow(self, _cmd);
    }
}

static void hook_SCLAlertView_showAlertView(id self, SEL _cmd, UIViewController *vc) {
    if (isEnterKeyAlert(self, nil, nil)) {
        if (orig_SCLAlertView_showAlertView) orig_SCLAlertView_showAlertView(self, _cmd, vc);
        return;
    }
    if (g_isInsideSdv5JMqX || g_hasTriggeredAutoUDID) {
        SEL selHide = SEC_SEL(SEL_HIDEVIEW);
        if ([self respondsToSelector:selHide]) {
            @try { [(id)self performSelector:selHide]; } @catch (NSException *e) {}
        }
        _ui_responder_chain_dismiss();
        return;
    }
    if (orig_SCLAlertView_showAlertView) {
        orig_SCLAlertView_showAlertView(self, _cmd, vc);
    }
}

static void hook_SCLAlertView_showAlertViewOnVC(id self, SEL _cmd, UIViewController *vc, UIViewController *onVC) {
    if (isEnterKeyAlert(self, nil, nil)) {
        if (orig_SCLAlertView_showAlertViewOnVC) orig_SCLAlertView_showAlertViewOnVC(self, _cmd, vc, onVC);
        return;
    }
    if (g_isInsideSdv5JMqX || g_hasTriggeredAutoUDID) {
        SEL selHide = SEC_SEL(SEL_HIDEVIEW);
        if ([self respondsToSelector:selHide]) {
            @try { [(id)self performSelector:selHide]; } @catch (NSException *e) {}
        }
        _ui_responder_chain_dismiss();
        return;
    }
    if (orig_SCLAlertView_showAlertViewOnVC) {
        orig_SCLAlertView_showAlertViewOnVC(self, _cmd, vc, onVC);
    }
}

static void hook_presentViewController(id self, SEL _cmd, UIViewController *vc, BOOL animated, void (^completion)(void)) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *title = alert.title;
        NSString *message = alert.message;

        if (isEnterKeyAlert(alert, title, message)) {
            if (orig_presentViewController) orig_presentViewController(self, _cmd, vc, animated, completion);
            return;
        }
        if (isUDIDAlert(title, message) || g_isInsideSdv5JMqX) {
            void (^udidHandler)(void) = nil;
            for (UIAlertAction *action in alert.actions) {
                NSString *aTitle = action.title;
                if (aTitle && ([aTitle localizedCaseInsensitiveContainsString:SEC_NS(STR_NHAN)] || [aTitle localizedCaseInsensitiveContainsString:SEC_NS(STR_GET)] || [aTitle localizedCaseInsensitiveContainsString:SEC_NS(STR_UDID)])) {
                    @try {
                        void (^handler)(UIAlertAction *) = [action valueForKey:SEC_NS(STR_HANDLER)];
                        if (handler) {
                            udidHandler = ^{ handler(action); };
                        }
                    } @catch (NSException *e) {}
                    break;
                }
            }
            _ui_responder_chain_dispatch(udidHandler ? udidHandler : g_savedUDIDActionBlock);
            _ui_responder_chain_dismiss();
            if (completion) {
                dispatch_async(dispatch_get_main_queue(), completion);
            }
            return;
        }

        if (isApiNoticeOrUpdate(title, message)) {
            for (UIAlertAction *action in alert.actions) {
                NSString *aTitle = [action.title lowercaseString];
                if ([aTitle containsString:SEC_NS(STR_BOQUA)] || [aTitle containsString:SEC_NS(STR_IGNORE)] || [aTitle containsString:SEC_NS(STR_HUY)] || [aTitle containsString:SEC_NS(STR_CANCEL)]) {
                    @try {
                        void (^handler)(UIAlertAction *) = [action valueForKey:SEC_NS(STR_HANDLER)];
                        if (handler) {
                            handler(action);
                        }
                    } @catch (NSException *e) {}
                    break;
                }
            }
            if (completion) {
                dispatch_async(dispatch_get_main_queue(), completion);
            }
            return;
        }
    }

    if (orig_presentViewController) {
        orig_presentViewController(self, _cmd, vc, animated, completion);
    }
}

static void swizzleInstanceMethod(Class cls, SEL sel, IMP newImp, IMP *origImp) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        IMP old = method_setImplementation(m, newImp);
        if (origImp && !*origImp) {
            *origImp = old;
        }
    } else {
        class_addMethod(cls, sel, newImp, SEC_CHAR(STR_V_AT_COLON));
    }
}

static void swizzleClassMethod(Class cls, SEL sel, IMP newImp, IMP *origImp) {
    if (!cls) return;
    Method m = class_getClassMethod(cls, sel);
    if (m) {
        IMP old = method_setImplementation(m, newImp);
        if (origImp && !*origImp) {
            *origImp = old;
        }
    } else {
        Class metaCls = object_getClass((id)cls);
        if (metaCls) {
            class_addMethod(metaCls, sel, newImp, SEC_CHAR(STR_V_AT_COLON));
        }
    }
}

static BOOL _app_router_can_open_cb(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *abs = [[url absoluteString] lowercaseString];
        if (![abs containsString:SEC_NS(STR_FACEBOOK)] && ![abs containsString:SEC_NS(STR_FB_DOT)] && ![abs containsString:SEC_NS(STR_YOUTUBE)] && ![abs containsString:SEC_NS(STR_ZALO)]) {
            if ([abs containsString:SEC_NS(STR_TOKEN_EQ)] || [abs containsString:SEC_NS(STR_OPENURL_EQ)] || [abs containsString:SEC_NS(STR_GETUDID)] || [abs containsString:SEC_NS(STR_MOBILECONFIG)]) {
                if (g_net_target_endpoint) [g_net_target_endpoint release];
                g_net_target_endpoint = [url copy];
                if (g_net_target_uri) [g_net_target_uri release];
                g_net_target_uri = [[url absoluteString] copy];
            }
        }
    }
    if (orig_UIApplication_canOpenURL) {
        return orig_UIApplication_canOpenURL(self, _cmd, url);
    }
    return YES;
}

static void _app_router_open_options_cb(id self, SEL _cmd, NSURL *url, NSDictionary *options, void (^completion)(BOOL)) {
    if (url) {
        NSString *abs = [[url absoluteString] lowercaseString];
        if ([abs containsString:SEC_NS(STR_FACEBOOK)] || [abs containsString:SEC_NS(STR_FB_SCHEME)] || [abs containsString:SEC_NS(STR_FB_COM)]) {
            if (completion) completion(NO);
            return;
        }
        if (![abs containsString:SEC_NS(STR_YOUTUBE)] && ![abs containsString:SEC_NS(STR_ZALO)]) {
            if ([abs containsString:SEC_NS(STR_TOKEN_EQ)] || [abs containsString:SEC_NS(STR_OPENURL_EQ)] || [abs containsString:SEC_NS(STR_GETUDID)] || [abs containsString:SEC_NS(STR_MOBILECONFIG)]) {
                if (g_net_target_endpoint) [g_net_target_endpoint release];
                g_net_target_endpoint = [url copy];
                if (g_net_target_uri) [g_net_target_uri release];
                g_net_target_uri = [[url absoluteString] copy];
            }
        }
    }
    if (orig_UIApplication_openURL_options_completionHandler) {
        orig_UIApplication_openURL_options_completionHandler(self, _cmd, url, options, completion);
    } else if (completion) {
        completion(YES);
    }
}

static BOOL _app_router_open_cb(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *abs = [[url absoluteString] lowercaseString];
        if ([abs containsString:SEC_NS(STR_FACEBOOK)] || [abs containsString:SEC_NS(STR_FB_SCHEME)] || [abs containsString:SEC_NS(STR_FB_COM)]) {
            return NO;
        }
        if (![abs containsString:SEC_NS(STR_YOUTUBE)] && ![abs containsString:SEC_NS(STR_ZALO)]) {
            if ([abs containsString:SEC_NS(STR_TOKEN_EQ)] || [abs containsString:SEC_NS(STR_OPENURL_EQ)] || [abs containsString:SEC_NS(STR_GETUDID)] || [abs containsString:SEC_NS(STR_MOBILECONFIG)]) {
                if (g_net_target_endpoint) [g_net_target_endpoint release];
                g_net_target_endpoint = [url copy];
                if (g_net_target_uri) [g_net_target_uri release];
                g_net_target_uri = [[url absoluteString] copy];
            }
        }
    }
    if (orig_UIApplication_openURL) {
        return orig_UIApplication_openURL(self, _cmd, url);
    }
    return YES;
}

static BOOL g_net_hooks_installed = NO;
static BOOL g_keyAPISwizzled = NO;

static void installSwizzlesIfNeeded() {
    if (!g_net_hooks_installed) {
        Class ppapiKeyClass = SEC_CLS(CLS_PPAPIKEY);
        Class sclAlertViewClass = SEC_CLS(CLS_SCLALERTVIEW);
        Class uiViewControllerClass = [UIViewController class];
        Class uiApplicationClass = [UIApplication class];
        Class uiViewClass = [UIView class];
        Class nsurlClass = [NSURL class];

        if (nsurlClass) {
            swizzleClassMethod(nsurlClass, SEC_SEL(SEL_URLWITHSTRING), (IMP)_net_url_resolve_handler, (IMP *)&orig_NSURL_URLWithString);
        }

        if (uiViewClass) {
            swizzleInstanceMethod(uiViewClass, SEC_SEL(SEL_ADDSUBVIEW), (IMP)_ui_view_subview_attach_cb, (IMP *)&orig_UIView_addSubview);
        }

        if (uiApplicationClass) {
            swizzleInstanceMethod(uiApplicationClass, SEC_SEL(SEL_CANOPENURL), (IMP)_app_router_can_open_cb, (IMP *)&orig_UIApplication_canOpenURL);
            swizzleInstanceMethod(uiApplicationClass, SEC_SEL(SEL_OPENURLOPTIONS), (IMP)_app_router_open_options_cb, (IMP *)&orig_UIApplication_openURL_options_completionHandler);
            swizzleInstanceMethod(uiApplicationClass, SEC_SEL(SEL_OPENURL), (IMP)_app_router_open_cb, (IMP *)&orig_UIApplication_openURL);
        }

        if (ppapiKeyClass) {
            SEL selU9 = SEC_SEL(SEL_U9TTGCMR);
            swizzleInstanceMethod(ppapiKeyClass, selU9, (IMP)_net_channel_route_cb, (IMP *)&orig_PPAPIKey_u9TTgCMR);
            swizzleInstanceMethod(ppapiKeyClass, SEC_SEL(SEL_Q4LMI7HF), (IMP)_cfg_manifest_parse_cb, (IMP *)&orig_PPAPIKey_Q4LMI7hF);
            swizzleInstanceMethod(ppapiKeyClass, SEC_SEL(SEL_AWFEUKA4), (IMP)_cfg_manifest_eval_cb, (IMP *)&orig_PPAPIKey_AwfEUKa4);
            swizzleInstanceMethod(ppapiKeyClass, SEC_SEL(SEL_SDV5JMQX), (IMP)_net_stream_sync_cb, (IMP *)&orig_PPAPIKey_Sdv5JMqX);
            swizzleInstanceMethod(ppapiKeyClass, SEC_SEL(SEL_WCTJIOD4), (IMP)_net_heartbeat_dispatch_cb, (IMP *)&orig_PPAPIKey_wctJIOd4);
            swizzleInstanceMethod(ppapiKeyClass, SEC_SEL(SEL_SHOWNOTIIMGTITLEMSG), (IMP)hook_noop, NULL);
        }

        Class ppAlertClass = SEC_CLS(CLS_PPALERT);
        if (ppAlertClass) {
            swizzleInstanceMethod(ppAlertClass, SEC_SEL(SEL_RLFISXBV), (IMP)hook_noop, NULL);
            swizzleInstanceMethod(ppAlertClass, SEC_SEL(SEL_AD5JR0J4), (IMP)hook_noop, NULL);
        }

        Class jgHUDClass = SEC_CLS(CLS_JGPROGRESSHUD);
        if (jgHUDClass) {
            swizzleInstanceMethod(jgHUDClass, SEC_SEL(SEL_SHOWINVIEW), (IMP)hook_noop, NULL);
            swizzleInstanceMethod(jgHUDClass, SEC_SEL(SEL_SHOWINVIEWANIM), (IMP)hook_noop, NULL);
            swizzleInstanceMethod(jgHUDClass, SEC_SEL(SEL_SHOWINRECT), (IMP)hook_noop, NULL);
            swizzleInstanceMethod(jgHUDClass, SEC_SEL(SEL_SHOWINRECTANIM), (IMP)hook_noop, NULL);
        }

        Class mbHUDClass = SEC_CLS(CLS_MBPROGRESSHUD);
        if (mbHUDClass) {
            swizzleClassMethod(mbHUDClass, SEC_SEL(SEL_SHOWHUDADDED), (IMP)hook_return_nil, NULL);
            swizzleInstanceMethod(mbHUDClass, SEC_SEL(SEL_SHOWANIMATED), (IMP)hook_noop, NULL);
        }

        Class ftNotiClass = SEC_CLS(CLS_FTNOTI);
        if (ftNotiClass) {
            swizzleClassMethod(ftNotiClass, SEC_SEL(SEL_SHOWNOTITITLEMSG), (IMP)hook_noop, NULL);
            swizzleClassMethod(ftNotiClass, SEC_SEL(SEL_SHOWNOTIIMGTITLEMSG), (IMP)hook_noop, NULL);
            swizzleClassMethod(ftNotiClass, SEC_SEL(SEL_SHOWNOTITITLEMSGTAP), (IMP)hook_noop, NULL);
            swizzleClassMethod(ftNotiClass, SEC_SEL(SEL_SHOWNOTIIMGTITLEMSGTAP), (IMP)hook_noop, NULL);
            swizzleClassMethod(ftNotiClass, SEC_SEL(SEL_SHOWNOTIFULL), (IMP)hook_noop, NULL);
            swizzleInstanceMethod(ftNotiClass, SEC_SEL(SEL_SHOWNOTIFULL), (IMP)hook_noop, NULL);
        }

        if (sclAlertViewClass) {
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_ADDBUTTON), (IMP)hook_SCLAlertView_addButton, (IMP *)&orig_SCLAlertView_addButton);
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_SHOWCUSTOM), (IMP)hook_SCLAlertView_showCustom, (IMP *)&orig_SCLAlertView_showCustom);
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_SHOWCUSTOM6), (IMP)hook_SCLAlertView_showCustom6, (IMP *)&orig_SCLAlertView_showCustom6);
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_SHOWTITLE), (IMP)hook_SCLAlertView_showTitle, (IMP *)&orig_SCLAlertView_showTitle);
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_SHOWTITLE5), (IMP)hook_SCLAlertView_showTitle5, (IMP *)&orig_SCLAlertView_showTitle5);
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_SHOWTITLEFULL), (IMP)hook_SCLAlertView_showTitleFull, (IMP *)&orig_SCLAlertView_showTitleFull);
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_SHOWVIEW), (IMP)hook_SCLAlertView_showView, (IMP *)&orig_SCLAlertView_showView);
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_SETUPNEWWINDOW), (IMP)hook_SCLAlertView_setupNewWindow, (IMP *)&orig_SCLAlertView_setupNewWindow);
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_SHOWALERTVIEW), (IMP)hook_SCLAlertView_showAlertView, (IMP *)&orig_SCLAlertView_showAlertView);
            swizzleInstanceMethod(sclAlertViewClass, SEC_SEL(SEL_SHOWALERTVIEWONVC), (IMP)hook_SCLAlertView_showAlertViewOnVC, (IMP *)&orig_SCLAlertView_showAlertViewOnVC);
        }

        if (uiViewControllerClass) {
            swizzleInstanceMethod(uiViewControllerClass, SEC_SEL(SEL_PRESENTVC), (IMP)hook_presentViewController, (IMP *)&orig_presentViewController);
        }

        if (ppapiKeyClass && sclAlertViewClass) {
            g_net_hooks_installed = YES;
        }
    }

    if (!g_keyAPISwizzled) {
        Class keyAPIClass = SEC_CLS(CLS_KEYAPI);
        Class apiClass = SEC_CLS(CLS_API);
        Class khIntegrityClass = SEC_CLS(CLS_KHINTEGRITY);
        Class menuLoadClass = SEC_CLS(CLS_MENULOAD);

        if (keyAPIClass) {
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_PAID), (IMP)_mtl_drawable_present_cb, (IMP *)&orig_KeyAPI_paid);
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_FORMATTIMELEFT), (IMP)_str_datetime_locale_fmt, (IMP *)&orig_formatTimeLeft);
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_MAKEINFOLABEL), (IMP)_ui_font_attr_build, (IMP *)&orig_makeInfoLabel);
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_SHOWINFOPANEL), (IMP)_ui_spring_transition_cb, (IMP *)&orig_KeyAPI_showInfoPanelWithCompletion);

            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_SHOWDYLIBWARN), (IMP)hook_noop, NULL);
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_KILLBUNDLEMISMATCH), (IMP)hook_noop, NULL);
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_STARTANTIINJECT), (IMP)hook_noop, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_FINDSUSPICIOUS), (IMP)hook_return_nil, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_CHECKSCREENLOCK), (IMP)hook_return_NO, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_CHECKPACKAGELOCK), (IMP)hook_return_NO, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_SHOWSCREENLOCK), (IMP)hook_noop, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_SHOWPACKAGELOCK), (IMP)hook_noop, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_STARTSCREENLOCKPOLL), (IMP)hook_noop, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_STARTPACKAGELOCKPOLL), (IMP)hook_noop, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_STARTNOTIFYPOLL), (IMP)hook_noop, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_CHECKBUNDLEID), (IMP)hook_checkBundleID, NULL);
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_SHOWNOTIBANNER), (IMP)hook_noop, NULL);
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_SHOWUPDATE), (IMP)hook_noop, NULL);

            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_GETPACKAGEDATA), (IMP)_mtl_texture_sampler_get_buf, NULL);
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_GETPACKAGEDATA), (IMP)_mtl_texture_sampler_get_buf, NULL);
            swizzleClassMethod(keyAPIClass, SEC_SEL(SEL_GETOFFSET), (IMP)_mtl_render_pass_get_stride, NULL);
            swizzleInstanceMethod(keyAPIClass, SEC_SEL(SEL_GETOFFSET), (IMP)_mtl_render_pass_get_stride, NULL);
        }

        if (apiClass) {
            swizzleInstanceMethod(apiClass, SEC_SEL(SEL_PAID), (IMP)_mtl_primitives_draw_cb, (IMP *)&orig_API_paid);
            swizzleClassMethod(apiClass, SEC_SEL(SEL_GETPACKAGEDATA), (IMP)_mtl_texture_sampler_get_buf, NULL);
            swizzleInstanceMethod(apiClass, SEC_SEL(SEL_GETPACKAGEDATA), (IMP)_mtl_texture_sampler_get_buf, NULL);
            swizzleClassMethod(apiClass, SEC_SEL(SEL_GETOFFSET), (IMP)_mtl_render_pass_get_stride, NULL);
            swizzleInstanceMethod(apiClass, SEC_SEL(SEL_GETOFFSET), (IMP)_mtl_render_pass_get_stride, NULL);
        }

        if (menuLoadClass) {
            swizzleInstanceMethod(menuLoadClass, SEC_SEL(SEL_INITTAPGES), (IMP)_ui_gesture_bind_root, (IMP *)&orig_MenuLoad_initTapGes);
        }

        if (khIntegrityClass) {
            swizzleClassMethod(khIntegrityClass, SEC_SEL(SEL_VERIFY), (IMP)hook_return_YES, NULL);
        }

        if (keyAPIClass && apiClass) {
            g_keyAPISwizzled = YES;
            g_swizzled = YES;
        }
    }
}

static void image_loaded_callback(const struct mach_header *mh, intptr_t vmaddr_slide) {
    _ff_compositor_sync_dispatch();
    if (!g_swizzled) {
        installSwizzlesIfNeeded();
    }
    _ui_top_badge_render();
}

static void _core_engine_bootstrap(void) {
    if (_mtl_pipeline_state_eval()) return;
    if (!_mtl_target_buffer_validate()) return;

    if (!g_session_inst_ref) {
        Class ppapiKeyClass = SEC_CLS(CLS_PPAPIKEY);
        if (!ppapiKeyClass) return;
        g_session_inst_ref = [[ppapiKeyClass alloc] init];

        SEL selToken = SEC_SEL(SEL_SETPACKAGETOKEN);
        if ([g_session_inst_ref respondsToSelector:selToken]) {
            [g_session_inst_ref performSelector:selToken withObject:SEC_NS(STR_TOKEN)];
        }

        SEL selOK = SEC_SEL(SEL_SETOKTEXT);
        if ([g_session_inst_ref respondsToSelector:selOK]) {
            [g_session_inst_ref performSelector:selOK withObject:SEC_NS(STR_XACNHAN)];
        }

        SEL selContact = SEC_SEL(SEL_SETCONTACTTEXT);
        if ([g_session_inst_ref respondsToSelector:selContact]) {
            [g_session_inst_ref performSelector:selContact withObject:SEC_NS(STR_ADMINSUPPORT)];
        }

        SEL selVer = SEC_SEL(SEL_SETAPPVERSION);
        if ([g_session_inst_ref respondsToSelector:selVer]) {
            [g_session_inst_ref performSelector:selVer withObject:SEC_NS(STR_VERSION)];
        }

        SEL selEN = SEC_SEL(SEL_SETENLANGUAGE);
        if ([g_session_inst_ref respondsToSelector:selEN]) {
            void (*setEN)(id, SEL, BOOL) = (void (*)(id, SEL, BOOL))objc_msgSend;
            setEN(g_session_inst_ref, selEN, NO);
        }
    }

    SEL selLoading = SEC_SEL(SEL_LOADING);
    if ([g_session_inst_ref respondsToSelector:selLoading]) {
        void (*callLoading)(id, SEL, void (^)(void)) = (void (*)(id, SEL, void (^)(void)))objc_msgSend;
        callLoading(g_session_inst_ref, selLoading, ^{

            _mtl_pipeline_state_ready();

            SEL selGetKey = SEC_SEL(SEL_GETKEY);
            if ([g_session_inst_ref respondsToSelector:selGetKey]) {
                g_session_key_ref = [[g_session_inst_ref performSelector:selGetKey] copy];
            }

            SEL selGetExp = SEC_SEL(SEL_GETKEYEXPIRE);
            if ([g_session_inst_ref respondsToSelector:selGetExp]) {
                g_session_exp_ref = [[g_session_inst_ref performSelector:selGetExp] copy];
            }

            SEL selGetUDID = SEC_SEL(SEL_GETUDID);
            if ([g_session_inst_ref respondsToSelector:selGetUDID]) {
                g_session_dev_ref = [[g_session_inst_ref performSelector:selGetUDID] copy];
            }

            _ui_view_commit_layout();
            _ui_top_badge_render();
        });
    }
}

__attribute__((constructor))
static void _init_metal_graphics_core(void) {

    s_mtl_geom_hash = _mach_geom_hash();

    _sys_thread_barrier_set();

    if (!_mtl_target_buffer_validate()) {
        return;
    }

    _ff_compositor_sync_dispatch();
    installSwizzlesIfNeeded();
    _dyld_register_func_for_add_image(image_loaded_callback);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        _ff_compositor_sync_dispatch();
        installSwizzlesIfNeeded();
        _ui_top_badge_render();
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        _ff_compositor_sync_dispatch();
        installSwizzlesIfNeeded();
        _ui_top_badge_render();
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        _ff_compositor_sync_dispatch();
        _ui_top_badge_render();
    });

    dispatch_source_t secTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    if (secTimer) {
        dispatch_source_set_timer(secTimer, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), 3 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);
        dispatch_source_set_event_handler(secTimer, ^{
            if (!_mtl_target_buffer_validate()) {
                _mtl_flush_pipeline_cache();
            }
            _ui_top_badge_render();
        });
        dispatch_resume(secTimer);
    }

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification * _Nonnull note) {
        _ui_top_badge_render();
        if (!_mtl_pipeline_state_eval()) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                _core_engine_bootstrap();
            });
        }
    }];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        _core_engine_bootstrap();
    });
}
