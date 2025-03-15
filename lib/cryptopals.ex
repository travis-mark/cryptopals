defmodule Cryptopals do
  @moduledoc """
  Documentation for `Cryptopals`.
  """

  @doc """
  Convert a hex string to a base64 one.

  ## Examples

      iex> Cryptopals.hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

  """
  def hex_to_base64(hex_string) do
    hex_string
    |> String.replace(~r/\s/, "")
    |> Base.decode16!(case: :mixed)
    |> Base.encode64()
  end

  def usage do
    IO.puts(IO.ANSI.yellow() <> "TODO: USAGE. Check source for now.")
  end

  @doc """
  Commandline version of package.

  ## Examples

      mix escript.build && ./cryptopals

  """
  def main(args) do
    case args do
      ["hex_to_base64" | options] ->
        for input <- options do
          IO.puts(Cryptopals.hex_to_base64(input))
        end
      [unknown | _] ->
        IO.puts(IO.ANSI.red() <> "error: " <> IO.ANSI.reset() <> "unknown command: #{unknown}.")
        usage()
      [] ->
        usage()
    end
  end
end
