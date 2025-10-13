defmodule IPSniffer do

  if Application.complie_env(:qsnmp, :ip_sniffer) do
    IO.puts """
    WARNING:
      You need to add :qsnmp / :ip_sniffer config information to your project. Copy or import
      configuration from 'deps/qsnmp/config/' to your config directory.

      ********************************************************
      *** The project will not compile until you make this ***
      ********************************************************
    """
  end

  require Logger

  # https://github.com/torvalds/linux/blob/v5.18/include/linux/socket.h#L195
  # @address_family 17
  # https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/if_ether.h#L131
  @eth_p 0x0003
  @socket_recv_buffer_size 1500

  defmacro set_vars() do
    opts = Application.get_env(:qsnmp, :ip_sniffer)
    Enum.map([:ip_protocol, :source_ip, :dest_ip, :source_port, :dest_port], fn key ->
      var = {key, [], nil}
      val = Keyword.get(opts, key, nil)
      quote do
        var!(unquote(var)) = unquote(val)
      end
    end)
  end

  defmacro packet_pattern() do
    opts = Application.get_env(:qsnmp, :ip_sniffer)
    {
      :<<>>,
      [], [
        quote do
          var!(_destination_mac)::binary-size(6)
        end,
        quote do
          var!(_source_mac)::binary-size(6)
        end,
        quote do
          0x0800::big-unsigned-integer-size(16)
        end,
        quote do
          4::unsigned-size(4)
        end,
        quote do
          var!(_ip_header_size)::unsigned-size(4)
        end,
        quote do
          var!(_ip_header_garbage1)::binary-size(8)
        end,
        quote do
          ^var!(ip_protocol)::unsigned-size(8)
        end,
        quote do
          var!(_ip_checksum)::big-unsigned-integer-size(16)
        end
      ] ++
      Enum.map([:source_ip, :dest_ip, :source_port, :dest_port], fn key ->
        val = Keyword.get(opts, key, nil)
        Code.string_to_quoted!("#{val && "^" || ""}var!(#{key})::#{String.match?("#{key}", ~r/_ip/) && "binary-size(4)" || "big-unsigned-integer-size(16)"}")
      end) ++
      [
        quote do
          var!(_length)::big-unsigned-integer-size(16)
        end,
        quote do
          var!(_checksum)::big-unsigned-integer-size(16)
        end,
        quote do
          var!(data)::binary
        end
      ]
    }
  end

  defmodule Socket do
    use Agent

    def start_link(socket) do
      Agent.start_link(fn ->
        socket
      end, name: __MODULE__)
    end

    def get() do
      Agent.get(__MODULE__, fn socket -> socket end)
    end

    def close() do
      socket = Agent.get(__MODULE__, fn socket -> socket end)
      :socket.close(socket)
    end
  end

  ######################################################################################
  ### Public API
  ######################################################################################
  def start(opts) do
    opts = opts ++ Application.get_env(:qsnmp, :ip_sniffer)
    case Keyword.get(opts, :ip_protocol) do
      nil ->
        raise(ArgumentError, message: "Missing option! 'ip_protocol' options is mandatory.")
      prot when not is_integer(prot) ->
        raise(ArgumentError, message: "Bad option! 'ip_protocol' must be an integer value.")
      prot ->
        prot
    end

    msg_type =
      case Keyword.get(opts, :inform_as) do
        nil ->
          raise(ArgumentError, message: "Missing option! 'inform_as' options is mandatory.")
        mst when not is_atom(mst) ->
          raise(ArgumentError, message: "Bad option! 'inform_as' must be an atom.")
        mst ->
          mst
      end

    receiver_pids =
      case Keyword.get(opts, :receiver_pids) do
        nil ->
          raise(ArgumentError, message: "Missing option! 'receiver_pid' options is mandatory.")
        pids when not (is_pid(pids) or is_list(pids)) ->
          raise(ArgumentError, message: "Bad option! 'receiver_pid' must be a proccess id or a list.")
        pid when is_pid(pid) ->
          [pid]
        pids ->
          pids
      end

    if_name = Keyword.get(opts, :if_name, :all)
    promiscuos = Keyword.get(opts, :promiscuous, false)

    socket = socket_open!(opts)
    socket_bind!(opts, socket, if_name, @eth_p)
    case promiscuos do
      true -> socket_set_promiscuous_mode!(socket, if_name)
      false -> :ok
    end

    Socket.start_link(socket)

    socket_receive(socket, {receiver_pids, 1}, msg_type)
  end

  ######################################################################################
  ### Private tools
  ######################################################################################
  defp socket_receive(socket, {pids, idx}, msg_type) do
    case :socket.recvfrom(socket, @socket_recv_buffer_size, :infinity)  do
      {:select, _} ->
        :ok

      {:error, reason} ->
        send(:lists.nth(idx, pids), {:socket_error, reason})

      packet ->
        # load filter vars: source_ip, dest_ip, source_port, dest_port
        set_vars()
        {source_ip, dest_ip, source_port, dest_port} # just for silent warnings
        case packet do
          {:ok, {_source, packet_pattern()}} ->
            Logger.log(:debug, "[IPSniffer] Sending message to #{inspect :lists.nth(idx, pids)}")
            send(:lists.nth(idx, pids), {
              msg_type,
              System.os_time(:second),
              source_ip |> :binary.bin_to_list() |> List.to_tuple,
              source_port,
              data
            })

          _ ->
            :ok
        end
    end
    idx = idx == length(pids) && 1 || idx + 1
    socket_receive(socket, {pids, idx}, msg_type)
  end

  defp socket_open!(opts) do
    # The protocol type must be provided in network byte order (big endian).
    # See https://man7.org/linux/man-pages/man7/packet.7.html for details
    <<eth_p_be::big-unsigned-integer-size(16)>> = <<@eth_p::native-unsigned-integer-size(16)>>
    {:ok, socket} = :socket.open(Keyword.get(opts, :ip_protocol), :raw, eth_p_be)
    socket
  end

  defp socket_bind!(_opts, _socket, :all, _eth_p), do: :ok
  defp socket_bind!(opts, socket, if_name, eth_p) do
    {:ok, if_index} = :binary.bin_to_list(if_name) |> :net.if_name2index()

    # Put real values only for sll_protocol and sll_ifindex.
    sll_protocol = eth_p
    sll_ifindex = if_index
    sll_hatype = 0
    sll_pkttype = 0
    sll_halen = 0
    sll_addr = <<0::native-unsigned-size(8)-unit(8)>>

    # The sockaddr_ll structure is described here https://man7.org/linux/man-pages/man7/packet.7.html
    addr = <<
      sll_protocol::big-unsigned-size(16),
      sll_ifindex::native-unsigned-size(32),
      sll_hatype::native-unsigned-size(16),
      sll_pkttype::native-unsigned-size(8),
      sll_halen::native-unsigned-size(8),
      sll_addr::binary
    >>

    sockaddr = %{
      family: Keyword.get(opts, :ip_protocol),
      addr: addr
    }

    :ok = :socket.bind(socket, sockaddr)
  end

  defp socket_set_promiscuous_mode!(_socket, :all), do: :ok
  defp socket_set_promiscuous_mode!(socket, if_name) do
    if_name = :binary.bin_to_list(if_name)
    :ok = :socket.ioctl(socket, :sifflags, if_name, %{promisc: true})
  end

end
