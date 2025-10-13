defmodule QSNMP.Utils do
  require Logger

  def pid_to_list(pid) do
    pid_inspection = "#{inspect pid}" # gives the string "#PID<0.105.0>"
    pid_inspection
      |> String.slice(5, 100)
      |> String.trim(">")
      |> String.split(".")
      |> Enum.map(fn x -> String.to_integer(x) end)
  end

  def csv2ets(file) do
    try do
      :ets.delete(:qsnmp_mibs)
    rescue
      _ -> :ok
    end
    table = :ets.new(:qsnmp_mibs, [:ordered_set, :named_table, :public, read_concurrency: true])
    file |> File.stream!() |> Stream.map(fn row ->
      [str_oid, num_str_oid] = row |> String.trim() |> String.split(";")
      num_list_oid = string_oid_to_list(num_str_oid)
      {str_oid, num_list_oid}
    end) |> Enum.map(fn record ->
      :ets.insert(table, record)
      :ets.insert(table, record |> Tuple.to_list() |> :lists.reverse() |> List.to_tuple())
    end)

    :ets.tab2file(table, file |> String.replace(".csv", ".ets") |> String.to_charlist())
    :ets.delete(table)
  end

  def string_oid_to_list(oid) when is_list(oid), do: oid
  def string_oid_to_list(oid) do
    [ oid1 |  oid2 ] = String.split(oid, "::")
    oid =
      (if oid2 == [], do: oid1, else: Enum.at(oid2, 0))
      |> String.trim()

    if String.match?(oid, ~r/[a-z]+/i) do
      [ oid |  rest ] = String.split(oid, ".")
      case QSNMP.MIBs.lookup(oid) do
        [] ->
          Logger.log(:error, "[SNMP]: Oid '#{oid}' does not exists!")
          nil
        [{_, noid}] ->
          noid ++ Enum.map(rest, &String.to_integer/1)
      end
    else
      oid |> String.split(".") |> Enum.map(&String.to_integer/1)
    end
  end

  def list_oid_to_string(oid, tail \\ [])
  def list_oid_to_string([], tail), do: tail
  def list_oid_to_string(oid, tail ) do
    case QSNMP.MIBs.lookup(oid) do
      [] ->
        list_oid_to_string(:lists.droplast(oid), [ :lists.last(oid) | tail ] )
      [{_, soid}] ->
        soid <> if length(tail) > 0, do: "." <> Enum.join(tail, "."), else: ""
    end
  end

    def encode_oid(<<6,8,43,_::binary>> = oid), do: oid
  def encode_oid(oid) when is_binary(oid) do
    oid
      |> string_oid_to_list()
      |> encode_oid()
  end
  def encode_oid(oid) when is_list(oid) do
    oid
      |> SnmpKit.PDU.Encoder.encode_oid_fast()
      |> elem(1)
  end


  def pdu_length_encode(len) when len > 127 do
    nb = ceil(len / 255)
    <<nb + 0x80, len::(nb*8)>>
  end
  def pdu_length_encode(len), do: <<len>>

end
