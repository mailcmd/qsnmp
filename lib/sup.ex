defmodule QSNMP.Supervisor do
  use Application

  def start(_, _) do
    children = [
      {QSNMP, []},
      {QSNMP.MIBs, []},
      {QSNMP.Receiver, []},
      {QSNMP.Emitter, []}
    ]

    opts = [strategy: :one_for_one, name: __MODULE__]
    Supervisor.start_link(children, opts)
  end
end
