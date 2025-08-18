#include <cstdio>
#include <windows.h>

#include "ghostteb.hpp"

void engine() {
    std::puts("GhostTEB | TEB/VEH Base Emulation (user-mode)");
    std::printf("[VALID] gs:[0x30] before: %p\n", ghost::read_gs30());

    void* real0 = ghost::read_gs30();

    if (!ghost::setup()) { std::puts("setup() failed");}

    ghost::read_fn target = &ghost::force_gs_read;
    if (!ghost::install((void*)target)) {
        std::puts("pattern not in local fn, using thunk..."); target = ghost::gs30_t();

        if (!target || !ghost::install((void*)target)) {std::puts("install failed"); ghost::uninstall();}
    }

    std::printf("Hooked @ %p (len=%u, dst=%u)\n",
    ghost::mov_site(), (unsigned)ghost::mov_len(), (unsigned)ghost::mov_dst());

    ghost::checkbytes(); ghost::checkveh(target);
    std::puts("\n[run] VEH Enabled:");

    for (int i = 0; i < 3; ++i) {
        void* v = target(); bool fake = (v != real0);

        std::printf("  %02d -> %p %s\n", i, v, fake ? "(SPOOF)" : "(REAL)");
        Sleep(50);
    }

    ghost::uninstall();
    std::printf("\n[Finished] returned gs:[0x30] -> %p (og: %p)\n",ghost::read_gs30(), real0);
}

auto main()->int { engine(); }
