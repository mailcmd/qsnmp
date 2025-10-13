import Config

config :logger,
  level: :info

config :logger, :default_formatter,
  format: "$time - [$level] $message $metadata\n"

config :qsnmp,
  ip_sniffer: [
    ip_protocol: 17,  # it is mandatory
    # source_ip: <<0,0,0,0>>,
    source_port: 161,
    # dest_ip: <<0,0,0,0>>,
    # dest_port: 161
    # if_name: :all # Interface where process listen
  ]
