-module(pcapfile).

%% API
-export([open/2, close/1, next/1, read_file/1, write_header/2, write/2, write/3]).

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
    end;
open(Filename, write) ->
    file:open(Filename, [write, raw]).

write_header(Device, Network) ->
    Major = 2,
    Minor = 4,
    GMT_to_localtime = 0,
    Sigfigs = 0,
    Data = <<?MAGIC:32, Major:16, Minor:16, GMT_to_localtime:32,
    Sigfigs:32, ?SNAPLEN:32, Network:32>>,
    file:write(Device, Data).

write(Device, Binary) ->
    {MegaSecs, Secs, _} = erlang:now(),
    Timestamp = MegaSecs * 1000000 + Secs,
    write(Device, Timestamp, Binary).

write(Device, Timestamp, Binary) ->
    Len = byte_size(Binary),
    Timestamp_us = (Timestamp rem 1000) * 1000,
    Data = <<Timestamp:32, Timestamp_us:32, Len:32, Len:32, Binary/binary>>,
    file:write(Device, Data).


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
