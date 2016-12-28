REBAR ?= rebar3

.PHONY: test doc

compile:
	@$(REBAR) compile

test:
	@$(REBAR) xref eunit

doc:
	@$(REBAR) doc

clean:
	@$(REBAR) clean

dialyzer:
	@$(REBAR) dialyzer
