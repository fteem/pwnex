defmodule Pwnex do
  @moduledoc """
  Consults haveibeenpwned.com's API for pwned passwords.
  """

  @doc """
  Checks if a given password is already pwned.

  ## Examples

      iex> Pwnex.pwned?("password")
      {:pwned, 3_533_661}

      iex> Pwnex.pwned?("m4Z2fJJ]r3fxQ*o27")
      {:ok, 0}

  """
  def pwned?(password) do
    {hash_head, hash_tail} =
      password
      |> sanitize
      |> hash
      |> split_password

    hash_head
    |> fetch_pwns
    |> handle_response
    |> build_pwns
    |> get_count(hash_tail)
    |> return_result
  end

  def split_password(hashed_password) do
    hash_head = hashed_password |> String.slice(0..4)
    hash_tail = String.replace_prefix(hashed_password, hash_head, "")
    {hash_head, hash_tail}
  end

  def sanitize(password), do: String.trim(password)

  def hash(password) do
    :crypto.hash(:sha, password)
    |> Base.encode16()
  end

  def fetch_pwns(head), do: :httpc.request('https://api.pwnedpasswords.com/range/#{head}')

  def handle_response({:ok, {_status, _headers, body}}), do: body
  def handle_response({:error, {reason, _meta}}), do: reason

  def build_pwns(response) do
    response
    |> to_string
    |> String.split()
    |> Enum.map(fn line -> String.split(line, ":") end)
    |> Enum.reduce(%{}, fn [hash, count], acc ->
      Map.put(acc, hash, String.to_integer(count))
    end)
  end

  def get_count(pwns, hash_tail), do: pwns[hash_tail]

  def return_result(count) when is_integer(count), do: {:pwned, count}
  def return_result(_), do: {:ok, 0}
end