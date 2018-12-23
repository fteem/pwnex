defmodule PwnexTest do
  use ExUnit.Case
  doctest Pwnex

  test "greets the world" do
    assert Pwnex.hello() == :world
  end
end
