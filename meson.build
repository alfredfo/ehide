project('ehide', 'c', version : '1.0.0',
        default_options : ['c_std=c89'])
cap_dep = dependency('libcap')
ehide = executable('ehide', 'main.c',
                   dependencies: [cap_dep],
                   install : true)
