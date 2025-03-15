defmodule CryptopalsTest do
  use ExUnit.Case
  doctest Cryptopals

  test "Convert hex to base64" do
    cases = [
      {
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
      }
    ]

    for {input, expected} <- cases do
      output = Cryptopals.hex_to_base64(input)

      assert output == expected,
             "Failed for input: #{input}, got: #{output}, expected: #{expected}"
    end
  end

  test "Fixed xor" do
    cases = [
      {
        "1c0111001f010100061a024b53535009181c",
        "686974207468652062756c6c277320657965",
        "746865206b696420646f6e277420706c6179"
      }
    ]

    for {input1, input2, expected} <- cases do
      output = Cryptopals.fixed_xor(input1, input2)

      assert output == expected,
             "Failed for input: #{input1} ^ #{input2}, got: #{output}, expected: #{expected}"
    end
  end
end
