project('t3fc', 'c', 'cpp', 
		version : '0.0.9999',
        license : 'BSD-3-Clause',
        default_options : ['cpp_std=c++17', 'c_std=c11'])

cppc = meson.get_compiler('cpp')
libcryptopp = dependency('libcrypto++', version : '>= 8.0')
fs = cppc.find_library('stdc++fs', required: true)

subdir('argon2')
subdir('nowide')

dependencies = [libcryptopp, fs]

executable('t3fc', 
		   sources : ['main.cpp'],
		   link_with : [libargon2, libnowide],
		   dependencies : dependencies,
           install : false)