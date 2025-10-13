defmodule QSNMP do
  @moduledoc """
  """

  @fix0 <<0x30>>
  @fix5 <<04>>
  @get <<0xA0>>
  @getnext <<0xA1>>
  @set <<0xA3>>
  @fix6n2 <<02,04>>
  @fix6n8 <<02,01,00,02,01,00>>
  @fix6n14 <<0x30>>
  @fix6n16 <<0x30>>
  @fix6nk_20 <<05,00>>

  @default_timeout 2500
  @default_max_repetitions 2

  require Logger

  import QSNMP.Utils
  alias QSNMP.Emitter

  defmodule Req do
    @default_timeout 2500
    @default_max_repetitions 2
    # @enforce_keys [:host, :community, :oids, :type]
    defstruct [
      :host,
      :community,
      :oids,
      :type,
      timeout: @default_timeout,
      max_repetitions: @default_max_repetitions,
      port: 161,
      version: 1,
      as_tuple: false,
      numeric_return: false
    ]
  end

  ################################################################################################
  ## INIT
  ################################################################################################

  def child_spec(_) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, []},
      type: :worker,
      restart: :permanent,
      shutdown: 500
    }
  end

  def start_link() do
    {:ok, spawn_link(fn -> init() end)}
  end

  def init() do
    Process.register(self(), :qsnmp_main)
    Process.sleep(:infinity)
  end

  ################################################################################################
  ## GET
  ################################################################################################

  # get/5
  def get(host, community, oids, timeout \\ @default_timeout, max_repetitions \\ @default_max_repetitions)
  def get(host, community, oids, timeout, max_repetitions) when is_binary(oids), do:
    get(host, community, String.split(oids, ~r/[ \t,]+/), timeout, max_repetitions)
  def get(host, community, oids, timeout, max_repetitions) do
    case cmd(%Req{
        host: host,
        community: community,
        oids: oids,
        timeout: timeout,
        max_repetitions: max_repetitions,
        type: @get,
        numeric_return: get_numeric_return(),
        version: 1
      }) do

      {:error, error} -> error
      result -> result
    end
  end
  def get(%Req{} = req), do: cmd(%Req{req | type: @get})

  # get2/5
  def get2(host, community, oids, timeout \\ @default_timeout, max_repetitions \\ @default_max_repetitions)
  def get2(host, community, oids, timeout, max_repetitions) when is_binary(oids), do:
    get2(host, community, String.split(oids, ~r/[ \t,]+/), timeout, max_repetitions)
  def get2(host, community, oids, timeout, max_repetitions) do
    case cmd(%Req{
        host: host,
        community: community,
        oids: oids,
        timeout: timeout,
        max_repetitions: max_repetitions,
        type: @get,
        numeric_return: get_numeric_return(),
        version: 2
      }) do

      {:error, error} -> error
      result -> result
    end
  end
  def get2(%Req{} = req), do: cmd(%Req{req | type: @get, version: 2})


  ################################################################################################
  ## GETNEXT
  ################################################################################################

  # getnext/5
  def getnext(host, community, oids, timeout \\ @default_timeout, max_repetitions \\ @default_max_repetitions)
  def getnext(host, community, oids, timeout, max_repetitions) when is_binary(oids), do:
    getnext(host, community, String.split(oids, ~r/[ \t,]+/), timeout, max_repetitions)
  def getnext(host, community, oids, timeout, max_repetitions) do
    case cmd(%Req{
        host: host,
        community: community,
        oids: oids,
        timeout: timeout,
        max_repetitions: max_repetitions,
        type: @getnext,
        numeric_return: get_numeric_return(),
        version: 1
      }) do

      {:error, error} -> error
      result -> result
    end
  end
  def getnext(%Req{} = req), do: cmd(%Req{req | type: @getnext})

  # getnext2/5
  def getnext2(host, community, oids, timeout \\ @default_timeout, max_repetitions \\ @default_max_repetitions)
  def getnext2(host, community, oids, timeout, max_repetitions) when is_binary(oids), do:
    get2(host, community, String.split(oids, ~r/[ \t,]+/), timeout, max_repetitions)
  def getnext2(host, community, oids, timeout, max_repetitions) do
    case cmd(%Req{
        host: host,
        community: community,
        oids: oids,
        timeout: timeout,
        max_repetitions: max_repetitions,
        type: @getnext,
        numeric_return: get_numeric_return(),
        version: 2
      }) do

      {:error, error} -> error
      result -> result
    end
  end
  def getnext2(%Req{} = req), do: cmd(%Req{req | type: @getnext, version: 2})

  ################################################################################################
  ## SET
  ################################################################################################

  # set/5
  def set(host, community, oids, timeout \\ @default_timeout, max_repetitions \\ @default_max_repetitions)
  def set(host, community, oids, timeout, max_repetitions) when is_binary(oids), do:
    set(host, community, String.split(oids, ~r/[ \t,]+/), timeout, max_repetitions)
  def set(host, community, oids, timeout, max_repetitions) do
    case cmd(%Req{
        host: host,
        community: community,
        oids: oids,
        timeout: timeout,
        max_repetitions: max_repetitions,
        type: @set,
        numeric_return: get_numeric_return(),
        version: 1
      }) do

      {:error, error} -> error
      result -> result
    end
  end
  def set(%Req{} = req), do: cmd(%Req{req | type: @set})

  # set2/5
  def set2(host, community, oids, timeout \\ @default_timeout, max_repetitions \\ @default_max_repetitions)
  def set2(host, community, oids, timeout, max_repetitions) when is_binary(oids), do:
    set2(host, community, String.split(oids, ~r/[ \t,]+/), timeout, max_repetitions)
  def set2(host, community, oids, timeout, max_repetitions) do
    case cmd(%Req{
        host: host,
        community: community,
        oids: oids,
        timeout: timeout,
        max_repetitions: max_repetitions,
        type: @set,
        numeric_return: get_numeric_return(),
        version: 2
      }) do

      {:error, error} -> error
      result -> result
    end
  end
  def set2(%Req{} = req), do: cmd(%Req{req | type: @set, version: 2})

  ################################################################################################
  ## WALK
  ################################################################################################

  def walk(%{} = req) do
    oid_base = string_oid_to_list(req[:oid])
    numeric_return =  if req[:numeric_return] != nil, do: req[:numeric_return], else: get_numeric_return()
    struct(%Req{}, req
      |> put_in([:oids], oid_base)
      |> put_in([:type], @getnext)
      |> put_in([:as_tuple], true)
      |> put_in([:numeric_return], true)
    )
    |> walk_h(oid_base, length(oid_base), numeric_return, req[:take] || -1)
  end
  def walk(host, community, oid, timeout \\ @default_timeout, max_repetitions \\ @default_max_repetitions, version \\ 1) do
    oid_base = string_oid_to_list(oid)
    req = %Req{
      host: host,
      community: community,
      oids: oid_base,
      timeout: timeout,
      max_repetitions: max_repetitions,
      type: @getnext,
      version: version,
      as_tuple: true,
      numeric_return: true
    }
    walk_h(req, oid_base, length(oid_base), get_numeric_return())
  end
  def walk2(host, community, oid, timeout \\ @default_timeout, max_repetitions \\ @default_max_repetitions) do
    walk(host, community, oid, timeout, max_repetitions, 2)
  end

  defp walk_h(req, oid_base, oid_len, numeric_return, count \\ -1, acc \\ [])
  defp walk_h(_, _, _, _, 0, acc), do: acc
  defp walk_h(req, oid_base, oid_len, numeric_return, count, acc) do
    with [{oid, val}] <- cmd(req),
          ^oid_base <- :lists.sublist(oid, oid_len) do

      oid_final = numeric_return && oid || list_oid_to_string(oid)
      walk_h(%{req|oids: oid}, oid_base, oid_len, numeric_return, count - 1, acc ++ [{oid_final, val}])
    else
      {:error, error} -> error
      _ -> acc
    end
  end

  ################################################################################################
  ## CMD (generic snmp call)
  ################################################################################################

  def cmd(%Req{max_repetitions: 0}), do: {:error, :timeout}
  def cmd(%Req{
    host: host,
    community: community,
    oids: oids,
    timeout: timeout,
    max_repetitions: max_repetitions,
    version: version,
    port: snmp_port,
    type: type,
    numeric_return: numeric_return
  } = req) do
    task = Task.async(fn ->
      [host, port | _] = String.split("#{host}:", ":")
      port =
        cond do
          port != "" -> String.to_integer(port)
          true -> snmp_port
        end

      version =
        case version do
          :v1 -> 1
          :v2 -> 2
          :v2c -> 2
          ver -> ver
        end

      {packet, req_id} = build_request(type, community, oids, version)
      send_request(host, port, packet)
      Logger.log(:debug, "[CMD-TASK] Sending packet and waiting response (#{inspect self()})")
      receive do
        %{pdu: %{request_id: ^req_id, varbinds: varbinds}} ->
          case {type, varbinds} do
            {@get, [varbind]} ->
              {_, _, value} = varbind
              value

            {_, varbinds} ->
              result = varbinds
                |> Stream.map(fn tuple -> Tuple.insert_at(tuple, 0, numeric_return) end)
                |> Stream.map(fn
                  {false, oid, _type, value} -> {list_oid_to_string(oid), value}
                  {_, oid, _type, value} -> {oid, value}
                end)

              if req.as_tuple,
                do: Enum.into(result, []),
                else: Enum.into(result, %{})

          end

        %{pdu: %{request_id: _}} ->
          {:error, :bad_reqid}

        _ ->
          {:error, :unknown}
      after
        timeout ->
          get(host, community, oids, timeout, max_repetitions-1)
      end
    end)
    Task.await(task, :infinity)
  end

  ################################################################################################
  # Tools
  ################################################################################################

  def set_numeric_return(set), do: Process.put(:numeric_return, set)
  def get_numeric_return(), do: Process.get(:numeric_return)

  # for back compatability
  def settings(:numeric_return, value), do: set_numeric_return(value)
  def settings(:numeric_return), do: get_numeric_return()


  ################################################################################################
  # Internal snmp tools
  ################################################################################################

  def build_request(type, community, oids, version \\ 1) do
    comm = <<byte_size(community)>> <> community
    [n0, n1, n2] = QSNMP.Utils.pid_to_list(self())
    req_id = <<n0::2, n1::28, n2::2>>

    varbinds = build_varbinds(type, oids)
    varbinds_size = varbinds |> byte_size() |> pdu_length_encode()

    req = @fix6n2 <> req_id <> @fix6n8 <> @fix6n14 <> varbinds_size <> varbinds
    req_size = req |> byte_size() |> pdu_length_encode()
    pack = <<2, 1, version-1>> <> @fix5 <> comm <> type <> req_size <> req
    pack_size = pack |> byte_size() |> pdu_length_encode()
    final_pack = pack_size <> pack
    <<req_id::signed-32>> = req_id
    {@fix0 <> final_pack, req_id}
  end

  ################################################################################################
  def build_varbinds(_type, []), do: <<>>
  ## SET
  def build_varbinds(@set, oid) when is_tuple(oid) or is_map(oid), do: build_varbinds(@set, [oid])
  def build_varbinds(@set, [%{} = oid | oids]) do
    %{oid: oid, type: type, value: value} = oid
    build_varbinds(@set, [{oid, type, value} | oids])
  end

  def build_varbinds(@set, [{oid, type, value} | oids]) do
    varbind = encode_oid(oid)  <> SnmpKit.PDU.Encoder.encode_snmp_value_fast(type, value)
    <<@fix6n16, byte_size(varbind)>> <> varbind <> build_varbinds(type, oids)
  end

  ## GET / GETNEXT
  def build_varbinds(type, [n | _] = oid) when is_integer(n), do: build_varbinds(type, [oid])
  def build_varbinds(type, [oid | oids]) do
    varbind = encode_oid(oid)  <> @fix6nk_20 # <<@type_get_set, byte_size(oid)>> <> oid <> @fix6nk_20
    <<@fix6n16, byte_size(varbind)>> <> varbind <> build_varbinds(type, oids)
  end

  ################################################################################################
  def send_request(host, port, request) do
    :gen_udp.send(Emitter.get(), to_charlist(host), port, request)
  end
end
