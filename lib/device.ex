defmodule ExWire.Device do
  @on_load :load_nifs

  @nifs [list_all: 0]

  def load_nifs() do
    :erlang.load_nif(~c"./libpcap/libexwire", 0)
  end

  def list_all() do
    raise "Not implemented"
  end
end
