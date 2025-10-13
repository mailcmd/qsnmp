defmodule QSNMP.Receiver do
  use Agent
  require Logger

  def start_link(_) do
    Agent.start_link(fn ->
      receive_pid = spawn_link(__MODULE__, :receiver, [])
      Process.register(receive_pid, :qsnmp_receiver)
      ip_sniffer_pid = spawn_link(fn ->
        if Process.whereis(IPSniffer.Socket), do: IPSniffer.Socket.close()
        IPSniffer.start(receiver_pids: [receive_pid], ip_protocol: 17, inform_as: :udp)
      end)
      Process.register(ip_sniffer_pid, :qsnmp_ip_sniffer)
      {receive_pid, ip_sniffer_pid}
    end, name: __MODULE__)
  end

  def get() do
    Agent.get(__MODULE__, fn status -> status end)
  end

  def status() do
    {receive_pid, _} = Agent.get(__MODULE__, fn status -> status end)
    {Process.alive?(receive_pid), :closed not in :socket.info(IPSniffer.Socket.get())[:wstates]}
  end

  def receiver() do
    receive do
      {_, _, _, _, message} ->
        Logger.log(:debug, "[Receiver] Receiving message from IPSniffer")
        {:ok, response} = SnmpKit.PDU.Decoder.decode_snmp_packet(message)
        Logger.log(:debug, "[Receiver] Message: #{inspect response}")
        <<n0::2, n1::28, n2::2>> = <<response.pdu.request_id::unsigned-32>>
        try do
          pid = "<#{n0}.#{n1}.#{n2}>" |> to_charlist() |> :erlang.list_to_pid()
          Logger.log(:debug, "[Receiver] Sending message to Task #{inspect pid} (#{inspect Process.alive?(pid)})")
          if Process.alive?(pid), do: send(pid, response)
        rescue
          _ -> :ok
        end
      msg ->
        Logger.log(:debug, "[Receiver] Unknown message from IPSniffer #{inspect msg}")
    end
    receiver()
  end
end
