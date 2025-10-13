defmodule QSNMP.MIBs do
  use Agent
  require Logger

  def start_link(_) do
    Agent.start_link(fn ->
      if (:ets.whereis(:qsnmp_mibs) == :undefined) do
        case :ets.file2tab(:code.priv_dir(:qsnmp) ++ ~c"/mibs2elixir.ets") do
          {:error, :cannot_create_table } -> {:ok, :qsnmp_mibs }
          {:error, _} ->
            Logger.log(:warning, "[QSNMP]: File 'priv/mibs2elixir.ets' does not exists")
            try do
              directory = :qsnmp |> :code.priv_dir() |> to_string()
              QSNMP.Utils.csv2ets(directory <> "/mibs2elixir.csv")
              :ets.file2tab(:code.priv_dir(:qsnmp) ++ ~c"/mibs2elixir.ets")
              Logger.log(:warning, "[QSNMP]: File 'priv/mibs2elixir.ets' created!")
            rescue
              e ->
                Logger.log(:error, "[QSNMP]: File 'priv/mibs2elixir.csv' does not exists #{inspect e}")
                raise("[QSNMP]: File 'priv/mibs2elixir.csv' does not exists #{inspect e}")
            end
          result ->
            result
        end
      end
    end, name: __MODULE__)
  end

  def check_table_opened() do
    if :ets.whereis(:qsnmp_mibs) == :undefined do
      :ets.file2tab(:code.priv_dir(:qsnmp) ++ ~c"/mibs2elixir.ets")
    end
  end

  def lookup(oid) do
    Agent.get(__MODULE__, fn _ ->
      check_table_opened()
      :ets.lookup(:qsnmp_mibs, oid)
    end)
  end

  def set_conf(key, value) do
    check_table_opened()
    :ets.insert(:qsnmp_mibs, {key, value})
  end

  def get_conf(key) do
    check_table_opened()
    case :ets.lookup(:qsnmp_mibs, key) do
      [{_, value}] -> value
      _ -> nil
    end
  end
end
