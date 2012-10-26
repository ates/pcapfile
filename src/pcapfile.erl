-module(pcapfile).

%% API
-export([open/2, close/1, next/1, read_file/1]).

-include("pcapfile.hrl").

-spec read_file(string()) -> {ok, #pcap{}} | {error, term()}.
read_file(Filename) ->
    {ok, Header, Device} = open(Filename, read),
    {ok, Records} = read_records(Device),
    {ok, #pcap{header = Header, records = Records}}.

-spec open(string(), read | write) ->
    {ok, #pcap_hdr{}, file:fd()} | {error, term()}.
open(Filename, read) ->
    case file:open(Filename, [read, binary]) of
        {ok, Device} ->
            {ok, Header} = read_header(Device),
            {ok, Header, Device};
        Error -> Error
    end.

-spec close(file:fd()) -> ok.
close(Device) ->
    ok = file:close(Device).

-spec next(file:fd()) -> {ok, #pcap_record{}}.
next(Device) ->
    read_record(Device).

-spec read_header(file:fd()) -> {ok, #pcap_hdr{}} | {error, term()}.
read_header(Device) ->
    case file:read(Device, ?PCAP_HEADER_SIZE) of
        {ok, <<?PCAP_HEADER_LITTLE>>} ->
            Header = #pcap_hdr{
                order = little,
                major = Major,
                minor = Minor,
                gmt_to_localtime = GMT_to_localtime,
                sigfigs = Sigfigs,
                snaplen = Snaplen,
                network = Network
            },
            {ok, Header};
        {ok, <<?PCAP_HEADER_BIG>>} ->
            Header = #pcap_hdr{
                order = big,
                major = Major,
                minor = Minor,
                gmt_to_localtime = GMT_to_localtime,
                sigfigs = Sigfigs,
                snaplen = Snaplen,
                network = Network
            },
            {ok, Header}
    end.

-spec read_records(file:fd()) -> {ok, [#pcap_record{}]} | {error, term()}.
read_records(Device) ->
    read_records(Device, []).

read_records(Device, Acc) ->
    case read_record(Device) of
        {ok, Record} ->
            read_records(Device, [Record | Acc]);
        eof ->
            close(Device),
            {ok, lists:reverse(Acc)};
        Error ->
            Error
    end.

-spec read_record(file:fd()) -> {ok, #pcap_record{}} | eof | {error, term()}.
read_record(Device) ->
    case file:read(Device, ?PCAP_RECORD_HEADER_SIZE) of
        %% XXX: Should be fixed
        {ok, <<?PCAP_RECORD_HEADER_LITTLE>>} when InclLen =< ?SNAPLEN ->
            {ok, Payload} = file:read(Device, InclLen),
            Record = #pcap_record{
                timestamp_s = Timestamp_s,
                timestamp_us = Timestamp_us,
                incl_len = InclLen,
                orig_len = OrigLen,
                truncated = is_truncated(InclLen, OrigLen),
                payload = Payload
            },
            {ok, Record};
        {ok, <<?PCAP_RECORD_HEADER_BIG>>} ->
            io:format("S: ~p~n", [InclLen]),
            {ok, Payload} = file:read(Device, InclLen),
            Record = #pcap_record{
                timestamp_s = Timestamp_s,
                timestamp_us = Timestamp_us,
                incl_len = InclLen,
                orig_len = OrigLen,
                truncated = is_truncated(InclLen, OrigLen),
                payload = Payload
            },
            {ok, Record};
        Error ->
            Error
    end.

-spec is_truncated(non_neg_integer(), non_neg_integer()) -> boolean().
is_truncated(InclLen, OrigLen) -> InclLen < OrigLen.
