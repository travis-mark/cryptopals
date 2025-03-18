defmodule CryptopalsTest do
  use ExUnit.Case
  doctest Cryptopals

  # https://cryptopals.com/sets/1/challenges/1
  test "Convert hex to base64" do
    input =
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

    output = input |> Cryptopals.decodeHex() |> Base.encode64()
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    assert output == expected,
           "Failed for input: #{input}, got: #{output}, expected: #{expected}"
  end

  # https://cryptopals.com/sets/1/challenges/2
  test "Fixed XOR" do
    string1 = "1c0111001f010100061a024b53535009181c" |> Cryptopals.decodeHex()
    string2 = "686974207468652062756c6c277320657965" |> Cryptopals.decodeHex()
    output = Cryptopals.fixedXor(string1, string2) |> Base.encode16(case: :lower)
    expected = "746865206b696420646f6e277420706c6179"

    assert output == expected,
           "Failed for input: #{string1} ^ #{string2}, got: #{output}, expected: #{expected}"
  end

  # https://cryptopals.com/sets/1/challenges/7
  test "AES in ECB mode" do
    {:ok, contents} = File.read("priv/7.txt")
    ciphertext = contents |> String.replace(~r/\s/, "") |> Base.decode64!()
    key = "YELLOW SUBMARINE"
    decoded = Cryptopals.aes_128_ecb(ciphertext, key)
    line1 = decoded |> String.split("\n", parts: 2) |> List.first()
    expected = "I'm back and I'm ringin' the bell "

    assert line1 == expected,
           "File decryption failed, got: #{line1}, expected: #{expected}"
  end

  # https://cryptopals.com/sets/1/challenges/8
  test "Detect AES in ECB mode" do
    # Line 133 (zero-based index)
    expected = 132

    {_, output} =
      File.stream!("priv/8.txt")
      |> Enum.with_index()
      |> Enum.filter(fn {line, _} -> duplicate_blocks?(line) end)

    assert expected == output,
           "Detect AES in ECB mode failed, got: #{output}, expected: #{expected}"
  end
end
