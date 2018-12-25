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
    |> find_pwns(hash_tail)
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

  def find_pwns(response, hash_tail) do
    response
    |> to_string
    |> String.split()
    |> Enum.find(&(String.starts_with?(&1, hash_tail)))
  end

  def return_result(line) when is_binary(line) do
    [_, count] = String.split(line, ":")
    {:pwned, count}
  end

  def return_result(_), do: {:ok, 0}
end
