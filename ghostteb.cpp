#include "ghostteb.hpp"

namespace ghost {

    struct st {
        void* real_teb = nullptr; void* fake_teb = nullptr;
        PVOID   veh = nullptr; uint8_t* mov = nullptr;

        uint8_t mov_n = 0; uint8_t mov_r = 0;
        uint8_t orig2[2]{ 0,0 }; uint8_t snap9[9]{ 0 };
    };
    static st g;

    bool write_bytes_rwx(void* p, const void* src, size_t n, uint8_t* prev) {
        if (!p || !src || !n) return false;
        RWX_SCOPE(p, n, { if (prev) std::memcpy(prev,p,n); std::memcpy(p,src,n); });
        return true;
    }
    bool write2(void* p, uint8_t b0, uint8_t b1, uint8_t* prev2) {
        const uint8_t t[2] = { b0,b1 }; return write_bytes_rwx(p, t, 2, prev2);
    }

    static inline DWORD64* reg_slot(CONTEXT& c, uint8_t idx) {
        static DWORD64 CONTEXT::* M[16] = {
            &CONTEXT::Rax,&CONTEXT::Rcx,&CONTEXT::Rdx,&CONTEXT::Rbx,
            nullptr,&CONTEXT::Rbp,&CONTEXT::Rsi,&CONTEXT::Rdi,
            &CONTEXT::R8,&CONTEXT::R9,&CONTEXT::R10,&CONTEXT::R11,
            &CONTEXT::R12,&CONTEXT::R13,&CONTEXT::R14,&CONTEXT::R15
        };
        return idx == 4 ? nullptr : &(c.*M[idx & 15]);
    }
    static inline bool put_reg(CONTEXT& c, uint8_t idx, uint64_t v) {
        if (auto* s = reg_slot(c, idx)) { *s = v; return true; } return false;
    }


    bool decode(const uint8_t* p, uint8_t& reg_out, uint8_t& len_out) {
        __try {
            if (!p || p[0] != 0x65) return false;                 
            uint8_t rex = p[1]; if ((rex & 0xF0) != 0x40 || (rex & 0x08) == 0) return false; // REX.W
            if (p[2] != 0x8B) return false;                      
            uint8_t m = p[3]; if ((m & 0xC0) != 0x00) return false;  
            if ((m & 0x07) != 0x04) return false;                 
            if (p[4] != 0x25) return false;                      
            if (*(uint32_t*)(p + 5) != GHOST_GS_OFF) return false; 
            reg_out = ((m >> 3) & 7) | ((rex & 0x04) ? 8 : 0);
            len_out = GHOST_MOV_LEN; return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    uint8_t* resolve(uint8_t* p) {
        for (int i = 0; i < 4; ++i) {
            __try {
                if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) p += 4;     // endbr64
                if (p[0] == 0x66 && p[1] == 0x90) p += 2;                             // 66 90
                if (p[0] == 0xE9) { p = p + 5 + *(int32_t*)(p + 1); continue; }          // jmp rel32
                if (p[0] == 0xEB) { p = p + 2 + *(int8_t*)(p + 1);  continue; }          // jmp rel8
                if (p[0] == 0xFF && p[1] == 0x25) {
                    int32_t d = *(int32_t*)(p + 2);      // jmp [rip+disp32]
                    p = *(uint8_t**)(p + 6 + d); continue;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { break; }
            break;
        }
        return p;
    }

    bool scanmov(void* fn, size_t max_scan, uint8_t*& site, uint8_t& dst, uint8_t& len) {
        auto* b = resolve((uint8_t*)fn);
        for (size_t i = 0; i + GHOST_MOV_LEN <= max_scan; ++i) {
            uint8_t r = 0, n = 0; if (decode(b + i, r, n)) { site = b + i; dst = r; len = n; return true; }
        }
        return false;
    }

    static LONG NTAPI veh(EXCEPTION_POINTERS* xp) {
        auto* c = xp->ContextRecord;
        if (xp->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
            if ((uint8_t*)c->Rip == g.mov) {
                put_reg(*c, g.mov_r, (uint64_t)g.fake_teb);
                c->Rip = (DWORD64)(g.mov + g.mov_n);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    read_fn gs30_t() {
        static const uint8_t code[] = { 0x65,0x48,0x8B,0x04,0x25,0x30,0,0,0,0xC3 };
        void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
           if (!mem) return nullptr; std::memcpy(mem, code, sizeof(code));
           FlushInstructionCache(GetCurrentProcess(), mem, sizeof(code)); return (read_fn)mem;
    }
    __declspec(noinline) void* force_gs_read() { return (void*)__readgsqword(GHOST_GS_OFF); }

    bool setup() {
        g.real_teb = read_gs30(); if (!g.real_teb) return false;
        g.fake_teb = VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g.fake_teb) return false;
        __try { std::memcpy(g.fake_teb, g.real_teb, 0x2000); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        g.veh = AddVectoredExceptionHandler(1, veh);

        if (!g.veh) { VirtualFree(g.fake_teb, 0, MEM_RELEASE); g.fake_teb = nullptr; return false; }
        return true;
    }

    bool install(void* fn) {
        uint8_t* site = nullptr; uint8_t dst = 0, len = 0;
        if (!scanmov(fn, GHOST_SCAN_MAX, site, dst, len)) return false;
        g.mov = site; g.mov_n = len; g.mov_r = dst;
        __try { std::memcpy(g.snap9, g.mov, 9); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        if (!write2(g.mov, GHOST_UD2_B0, GHOST_UD2_B1, g.orig2)) { g.mov = nullptr; return false; }
        return true;
    }

    void uninstall() {
        if (g.mov) { write2(g.mov, g.orig2[0], g.orig2[1], nullptr); g.mov = nullptr; }
        if (g.veh) { RemoveVectoredExceptionHandler(g.veh); g.veh = nullptr; }
        if (g.fake_teb) { VirtualFree(g.fake_teb, 0, MEM_RELEASE); g.fake_teb = nullptr; }
        g.real_teb = nullptr; g.mov_n = 0; g.mov_r = 0;
    }


    void checkbytes() {
        std::puts("\n[verify] 9B before patch:"); hex_dump(g.snap9, 9);
        uint8_t now[9]{}; __try { std::memcpy(now, g.mov, 9); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        std::puts("[verify] 9B after  patch:"); hex_dump(now, 9);
        bool ok = (now[0] == GHOST_UD2_B0 && now[1] == GHOST_UD2_B1);
        std::printf("[verify] head = %s\n", ok ? "UD2 OK" : "UNEXPECTED");
    }

    void checkveh(read_fn target) {
        std::puts("\n[check]   VEH disable test");
        PVOID h = g.veh; RemoveVectoredExceptionHandler(h); g.veh = nullptr;
        __try { (void)target(); std::puts("  unexpected: call returned"); }
        __except (GetExceptionCode() == STATUS_ILLEGAL_INSTRUCTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            std::puts("[success] STATUS_ILLEGAL_INSTRUCTION");
        }
        g.veh = AddVectoredExceptionHandler(1, veh);
        std::puts(g.veh ? "[success] VEH restored" : "[critical]  VEH restore has failed");
    }

    void* mov_site() { return g.mov; } uint8_t mov_len() { return g.mov_n; } uint8_t mov_dst() { return g.mov_r; }
    
   

} 
