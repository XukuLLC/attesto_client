defmodule AttestoClient.ClientAuthOptions do
  @moduledoc false

  @assertion_options ~w(audience alg kid typ lifetime now jti)a
  @attestation_options ~w(audience challenge alg kid lifetime now jti)a

  @spec valid?(term(), :assertion | :attestation) :: boolean()
  def valid?(opts, kind) when is_list(opts) and kind in [:assertion, :attestation] do
    allowed = if kind == :assertion, do: @assertion_options, else: @attestation_options

    Keyword.keyword?(opts) and Enum.all?(Keyword.keys(opts), &(&1 in allowed)) and
      length(opts) == length(Enum.uniq_by(opts, &elem(&1, 0)))
  end

  def valid?(_opts, _kind), do: false
end
