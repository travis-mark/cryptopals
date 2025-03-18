defmodule CryptopalsTest do
  use ExUnit.Case
  doctest Cryptopals

  # https://cryptopals.com/sets/1/challenges/1
  test "Convert hex to base64" do
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    output = input |> Cryptopals.decodeHex() |> Base.encode64()
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert output == expected,
             "Failed for input: #{input}, got: #{output}, expected: #{expected}"
  end

  # https://cryptopals.com/sets/1/challenges/2
  test "Fixed XOR" do
    string1 = "1c0111001f010100061a024b53535009181c" |> Cryptopals.decodeHex()
    string2 = "686974207468652062756c6c277320657965"|> Cryptopals.decodeHex()
    output = Cryptopals.fixedXor(string1, string2) |> Base.encode16(case: :lower)
    expected = "746865206b696420646f6e277420706c6179"
    assert output == expected,
             "Failed for input: #{string1} ^ #{string2}, got: #{output}, expected: #{expected}"
  end
end
