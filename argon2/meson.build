libargon2_sources = files('''
    core.c
    thread.c
    opt.c
    encoding.c
    blake2b.c
    argon2.c
'''.split())

threads = dependency('threads')
dependencies = [threads]

libargon2 = static_library('argon2',
                           libargon2_sources,
                           dependencies : dependencies)