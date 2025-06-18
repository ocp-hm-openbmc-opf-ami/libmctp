headers = [
  '.',
  '../../',
  '../../ctrld',
  '../../mctp-common-api',
]

# Sources for the library
sources = ['onPCIeDiscovery.c']

comp = meson.get_compiler('c')

# Install the header files
# install_headers('example.h')

systemd = declare_dependency(dependencies: [comp.find_library('systemd')])
i2c = declare_dependency(dependencies: [comp.find_library('i2c')])

# Shared library target
libmctp_turin_extensions = shared_library('mctp_PDK_turin',
  sources,
  include_directories : include_directories(headers),
  dependencies: [systemd, i2c],
  install : true,
  version : '1.0.0',          # Library version
  soversion : '1',             # API version
  link_with : [libmctp_common_api]
)


