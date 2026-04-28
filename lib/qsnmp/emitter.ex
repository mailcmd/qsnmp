defmodule QSNMP.Emitter do
  use Agent

  @port Application.compile_env(:qsnmp, :emitter_port, 1161)

  def start_link(_) do
    Agent.start_link(fn ->
      {:ok, socket} = :gen_udp.open(@port, [:binary, active: false, broadcast: false])
      socket
    end, name: __MODULE__)
  end

  def get() do
    Agent.get(__MODULE__, fn socket -> socket end)
  end
end
