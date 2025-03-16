defmodule Cryptopals do
  @moduledoc """
  Documentation for `Cryptopals`.
  """

  def hex_string_to_binary(hex_string) do
    hex_string
    |> String.replace(~r/\s/, "")
    |> Base.decode16!(case: :mixed)
  end

  @doc """
  Convert a hex string to a base64 one.

  ## Examples

      iex> Cryptopals.hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

  """
  def hex_to_base64(hex_string) do
    hex_string
    |> hex_string_to_binary
    |> Base.encode64()
  end

  @doc """
  Takes two equal-length buffers and produces their XOR combination.

  ## Examples

      iex> Cryptopals.fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
      "746865206b696420646f6e277420706c6179"
  """
  def fixed_xor(hex1, hex2) do
    binary1 = hex1
    |> hex_string_to_binary
    |> :binary.decode_unsigned
    binary2 = hex2
    |> hex_string_to_binary
    |> :binary.decode_unsigned
    Bitwise.bxor(binary1, binary2)
    |> :binary.encode_unsigned
    |> Base.encode16()
    |> String.downcase() # Causes test to pass, not sure if I want
  end

  def single_byte_xor(binary, cipher) do
    bytes = byte_size(binary)
    input = binary |> :binary.decode_unsigned
    key = :binary.decode_unsigned(for _ <- 1..bytes, into: <<>>, do: <<cipher>>)
    Bitwise.bxor(input, key) |> :binary.encode_unsigned
  end

  @english_character_freq %{
    ?a => 8.167,
    ?b => 1.492,
    ?c => 2.802,
    ?d => 4.271,
    ?e => 12.702,
    ?f => 2.228,
    ?g => 2.015,
    ?h => 6.094,
    ?i => 6.966,
    ?j => 0.153,
    ?k => 0.772,
    ?l => 4.025,
    ?m => 2.406,
    ?n => 6.749,
    ?o => 7.507,
    ?p => 1.929,
    ?q => 0.095,
    ?r => 5.987,
    ?s => 6.327,
    ?t => 9.056,
    ?u => 2.758,
    ?v => 0.978,
    ?w => 2.360,
    ?x => 0.150,
    ?y => 1.974,
    ?z => 0.074,
    ?\s => 13.000
  }

  def score_binary_for_english(binary) do
    total = binary
    |> :binary.bin_to_list()
    |> Enum.map(fn char -> Map.get(@english_character_freq, char, -10.0) end)
    |> Enum.sum()
    total / byte_size(binary)
  end

  @doc """
  [Set 1 / Challenge 3](https://cryptopals.com/sets/1/challenges/3)
  Given a hex encoded string, test for single character key.

  ## Examples

      iex> Cryptopals.single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
      {88, "Cooking MC's like a pound of bacon"}
  """
  def single_byte_xor_cipher(hex_string) do
    binary = hex_string |> hex_string_to_binary
    candidate = 0..255
    |> Enum.map(fn char ->
      output = single_byte_xor(binary, char)
      score = score_binary_for_english(output)
      {char, output, score}
    end)
    |> Enum.max(fn {_, _, score1}, {_, _, score2} -> score1 > score2 end)
    {key, output, _} = candidate
    {key, output}
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
