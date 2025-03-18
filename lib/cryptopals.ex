defmodule Cryptopals do
  @moduledoc """
  """

  @doc """
  Cryptopals Rule: Always operate on raw bytes, never on encoded strings.

  Convert hex to binary for processing.

  ## Examples

      iex> Cryptopals.decodeHex("68656c6c6f")
      "hello"
      iex> Cryptopals.decodeHex("68656c6c6f00") # \0 to force binary output
      <<104, 101, 108, 108, 111, 0>>
  """
  def decodeHex(string) do
    string
    |> String.replace(~r/\s/, "")
    |> Base.decode16!(case: :mixed)
  end

  @doc """
  Takes two equal-length strings and produces their XOR combination.

  ## Examples

      iex> Cryptopals.fixedXor("heat", "XUQD")
      "0000"
  """
  def fixedXor(left, right) do
    binary1 = left |> :binary.decode_unsigned()
    binary2 = right |> :binary.decode_unsigned()
    Bitwise.bxor(binary1, binary2) |> :binary.encode_unsigned()
  end

  @doc """
  XOR a string against a single byte

  ## Examples

      iex> "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" |> Cryptopals.decodeHex() |> Cryptopals.single_byte_xor(88)
      "Cooking MC's like a pound of bacon"
  """
  def single_byte_xor(binary, cipher) do
    bytes = byte_size(binary)
    input = binary |> :binary.decode_unsigned()
    key = :binary.decode_unsigned(for _ <- 1..bytes, into: <<>>, do: <<cipher>>)
    Bitwise.bxor(input, key) |> :binary.encode_unsigned()
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
    ?M => 2.406,
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
    total =
      binary
      |> :binary.bin_to_list()
      |> Enum.map(fn char -> Map.get(@english_character_freq, char, -10.0) end)
      |> Enum.sum()

    total / byte_size(binary)
  end

  def single_byte_xor_cipher(binary) do
    candidate =
      0..255
      |> Enum.map(fn char ->
        output = single_byte_xor(binary, char)
        score = score_binary_for_english(output)
        {char, output, score}
      end)
      |> Enum.max(fn {_, _, score1}, {_, _, score2} -> score1 > score2 end)

    {key, output, _} = candidate
    {key, output}
  end

  @doc """
  [Set 1 / Challenge 3](https://cryptopals.com/sets/1/challenges/3)
  Given a hex encoded string, test for a single character key.

  ## Examples

      iex> Cryptopals.hex_single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
      {88, "Cooking MC's like a pound of bacon"}
  """
  def hex_single_byte_xor_cipher(hex_string) do
    hex_string |> Cryptopals.decodeHex() |> single_byte_xor_cipher
  end

  def is_english(binary) do
    score_binary_for_english(binary) > 0
  end

  @doc """
  [Set 1 / Challenge 4](https://cryptopals.com/sets/1/challenges/4)
  Detect single-character XOR in a file.

  ## Examples

      iex> Cryptopals.detect_single_character_xor_cypher_in_path("priv/4.txt")
      [{53, "Now that the party is jumping\\n"}]
  """
  def detect_single_character_xor_cypher_in_path(path) do
    File.stream!(path)
    |> Enum.map(&Cryptopals.decodeHex/1)
    |> Enum.map(&Cryptopals.single_byte_xor_cipher/1)
    |> Enum.filter(fn {_, output} -> is_english(output) end)
  end

  @doc """
  [Set 1 / Challenge 5](https://cryptopals.com/sets/1/challenges/5)
  XOR a binary against a cypher by repeating it.

  ## Examples

      iex> Cryptopals.repeating_key_xor("Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal", "ICE") |> Base.encode16(case: :lower)
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
  """
  def repeating_key_xor(binary, cypher) do
    bytelist = binary |> :binary.bin_to_list()
    cycle = cypher |> :binary.bin_to_list() |> Stream.cycle()

    Enum.zip(bytelist, cycle)
    |> Enum.map(fn {left, right} -> Bitwise.bxor(left, right) end)
    |> :binary.list_to_bin()
  end

  @doc """
  Count the bits of an integer

  ## Examples

      iex> Cryptopals.count_bits(3)
      2
  """
  def count_bits(n) do
    count_bits(n, 0)
  end

  defp count_bits(0, acc), do: acc

  defp count_bits(n, acc) do
    new_acc = acc + Bitwise.band(n, 1)
    count_bits(Bitwise.bsr(n, 1), new_acc)
  end

  @doc """
  Hamming distance between the bits of two strings

  ## Examples

      iex> Cryptopals.bitwise_hamming_distance("this is a test", "wokka wokka!!!")
      37
  """
  def bitwise_hamming_distance(left, right) do
    Enum.zip(left |> :binary.bin_to_list(), right |> :binary.bin_to_list())
    |> Enum.map(fn {left, right} -> Bitwise.bxor(left, right) |> count_bits() end)
    |> Enum.sum()
  end

  def repeating_key_xor_possible_key_sizes(binary) do
    2..min(40, floor(byte_size(binary) / 2))
    |> Enum.map(fn sz ->
      left = binary_part(binary, 0, sz)
      right = binary_part(binary, sz, sz)
      {sz, Cryptopals.bitwise_hamming_distance(left, right) / sz}
    end)
  end

  def repeating_key_xor_detect_key_size(binary) do
    {key_size, _} =
      repeating_key_xor_possible_key_sizes(binary)
      |> Enum.min(fn {_, left}, {_, right} -> left < right end)

    key_size
  end

  @doc """
  Given an encoded binary, test for a repeating key.

  ## Examples

      iex> "1e15090d0442012b170509010a0d6d0402084f0b4f39001e" |> Cryptopals.decodeHex() |> Cryptopals.repeating_key_xor("Mellon!")
      "Speak, friend, and enter"
  """
  def repeating_key_xor_cipher(binary) do
    key_size = repeating_key_xor_detect_key_size(binary)
    repeating_key_xor_cipher(binary, key_size)
  end

  def repeating_key_xor_cipher(binary, key_size) do
    key =
      0..(key_size - 1)
      |> Enum.map(fn chunk_index ->
        binary
        |> :binary.bin_to_list()
        |> Enum.with_index()
        |> Enum.filter(fn {_, index} -> rem(index, key_size) == chunk_index end)
        |> Enum.map(fn {byte, _} -> byte end)
        |> :binary.list_to_bin()
        |> single_byte_xor_cipher()
      end)
      |> Enum.map(fn {byte, _} -> byte end)
      |> :binary.list_to_bin()

    {key, repeating_key_xor(binary, key)}
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
      [unknown | _] ->
        IO.puts(IO.ANSI.red() <> "error: " <> IO.ANSI.reset() <> "unknown command: #{unknown}.")
        usage()

      [] ->
        usage()
    end
  end
end
