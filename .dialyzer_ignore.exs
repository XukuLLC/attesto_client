# JOSE documents a two-tuple boolean result, but its verification boundary can
# still return unexpected terms after malformed input reaches the Erlang layer.
# Keep the catch-all so every public verifier fails closed instead of raising.
[
  {"lib/attesto_client/verifier.ex", :pattern_match_cov}
]
