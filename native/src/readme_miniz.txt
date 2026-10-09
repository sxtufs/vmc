Vendored miniz - inflate for the VMC container

vmp.cpp includes "miniz.h" and CMakeLists.txt compiles src/miniz.c, so the
runtime inflates the per-blob deflate streams in the VMPC container WITHOUT
linking zlib (the whole point: no libz DT_NEEDED - see the CI artifact checks).

miniz.c and miniz.h ARE committed here (native/src/), the single-file
amalgamation, unmodified. Version: miniz 3.1.2 (internal MZ_VERSION 11.3.2).
Only the tinfl_* API is used by vmp.cpp; the rest of the amalgamation is dead
code the linker drops via --gc-sections. Do not edit miniz.* - to update,
replace BOTH files from a fresh release amalgamation:
  https://github.com/richgel999/miniz/releases
