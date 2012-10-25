REBAR = ./rebar

.PHONY: test

compile:
	@$(REBAR) compile

test:
	@$(REBAR) xref eunit
