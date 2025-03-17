defmodule CryptopalsTest do
  use ExUnit.Case
  doctest Cryptopals

  test "Convert hex to base64" do
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert Cryptopals.hex_to_base64(input) == expected, "Convert hex to base64 failed"
  end

  test "Fixed XOR" do
    input1 = "1c0111001f010100061a024b53535009181c"
    input2 = "686974207468652062756c6c277320657965"
    expected = "746865206b696420646f6e277420706c6179"
    assert Cryptopals.fixed_xor(input1, input2) == expected, "Fixed XOR failed"
  end

  test "Single-byte XOR cipher" do
    input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    expected = {88, "Cooking MC's like a pound of bacon"}
    assert Cryptopals.single_byte_xor_cipher(input) == expected, "Single-byte XOR cipher failed"
  end

  test "Detect single-character XOR" do
    expected = [{53, "Now that the party is jumping\n"}]
    assert Cryptopals.detect_single_character_xor_cypher == expected, "Detect single-character XOR failed"
  end
end
