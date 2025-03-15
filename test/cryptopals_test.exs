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
end
