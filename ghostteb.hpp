#pragma once
#include <intrin.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <windows.h>


namespace ghost {

#define GHOST_SCAN_MAX   256u
#define GHOST_GS_OFF     0x30u
#define GHOST_MOV_LEN    9u
#define GHOST_UD2_B0     0x0F
#define GHOST_UD2_B1     0x0B

#ifndef STATUS_ILLEGAL_INSTRUCTION
#define STATUS_ILLEGAL_INSTRUCTION ((DWORD)0xC000001D)
#endif

	using read_fn = void* (*)();
	static inline void* read_gs30() { return (void*)__readgsqword(GHOST_GS_OFF); }

	read_fn gs30_t();
	__declspec(noinline) void* force_gs_read();


	bool      setup();
	bool      install(void* fn);
	void      uninstall();
	void      checkbytes();
	void      checkveh(read_fn target);

	void* mov_site();  uint8_t   mov_len(); uint8_t   mov_dst();
} 

#define RWX_SCOPE(p,n, BODY)                                                  \
do{ DWORD __old=0; if(VirtualProtect((p),(n),PAGE_EXECUTE_READWRITE,&__old)){ \
      { BODY } FlushInstructionCache(GetCurrentProcess(),(p),(n));            \
      DWORD __tmp=0; VirtualProtect((p),(n),__old,&__tmp);                    \
    }                                                                         \
}while(0)

inline void hex_dump(const uint8_t* p, size_t n) {
	for (size_t i = 0; i < n; ++i) std::printf("%02X%c", (unsigned)p[i], i + 1 < n ? ' ' : '\n');
}
