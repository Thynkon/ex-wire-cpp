defmodule ExWire do
  @on_load :load_nifs

  def load_nifs() do
    :erlang.load_nif(~c"./libpcap/libpcap", 0)
  end

  def add(_a, _b) do
    raise "Not implemented"
  end
end
