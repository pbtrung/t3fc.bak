project('t3fc', 'c', 'cpp', 
		version : '0.0.9999',
        license : 'BSD-3-Clause',
        default_options : ['cpp_std=c++17', 'c_std=c11'])

cppc = meson.get_compiler('cpp')
cc = meson.get_compiler('c')

args = '''
	-march=native
    -D_M_X64
'''.split()
foreach arg: args
    if cppc.has_argument(arg)
        add_project_arguments(arg, language : 'cpp')
    endif
    if cc.has_argument(arg)
        add_project_arguments(arg, language : 'c')
    endif
endforeach

subdir('cppcrypto')
subdir('nowide')

executable('t3fc', 
		   sources : ['main.cpp', 'randombytes/randombytes.c'],
		   link_with : [libcppcrypto, libnowide],
           install : false)