headers = [
  '.',
  '..',
  '../ctrld',
]

# Sources for the library
lib_sources = [
          'mctp-discovery-busowner.c',
          'mctp-discovery-endpoint.c',
          'mctp-host-state.c',
          'mctp-i2c-arp.c',
          'mctp-requester.c',
          'mctp-responder.c',
          'mctp-ext-socket.c',
          'mctp-share-routing-table.c',
          '../log.c',
          '../ctrld/mctp-discovery-common.c',
          '../ctrld/mctp-encode.c',
          '../ctrld/dbus_log_event.c',
          'mctp-utils.c',
          'mctp-ext-sdbus.c',
          'mctp-share-mutex.c'
          ]

comp = meson.get_compiler('c')

# Install the header files
# install_headers('mctp-discovery-endpoint.h')

systemd = declare_dependency(dependencies: [comp.find_library('systemd')])
i2c = declare_dependency(dependencies: [comp.find_library('i2c')])

# Shared library target
libmctp_common_api = shared_library('mctp_common_api',
  lib_sources,
  include_directories : include_directories(headers),
  dependencies: [systemd, i2c],  
  install : true,
  version : '1.0.0',          # Library version
  soversion : '1'             # ABI version
)