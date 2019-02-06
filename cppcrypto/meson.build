libcppcrypto_sources = files('''
	argon2.cpp
	blake.cpp
	blake2.cpp
	blake2b.c
	blake2s.c
	blake256-sse2.c
	blake256-sse41.c
	blake512-sse2.c
	blake512-sse41.c
	block_cipher.cpp
	cbc.cpp
    ctr.cpp
	cpuinfo.cpp
	crypto_hash.cpp
	hmac.cpp
	kalyna.cpp
	kupyna.cpp
	pbkdf2.cpp
	skein512.cpp
	skein512mmx.cpp
	thread_pool.cpp
	threefish.cpp
'''.split())

threads = dependency('threads')
dependencies = [threads]

yasm = find_program('yasm')
gen = generator(yasm,
	output : '@BASENAME@.o',
	arguments : ['-f', 'elf64', '@INPUT@', '-o', '@OUTPUT@'])
asm = gen.process('b256avxs.asm')

libcppcrypto = static_library('cppcrypto',
                              [libcppcrypto_sources, asm],
                              dependencies : dependencies)