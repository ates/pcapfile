-module(pcapfile).

%% API
-export([open/1, open/2, close/1, read_file/1]).
-export([next/1, write/2, write/3]).

-include("pcapfile.hrl").

%% @doc Opens the file and returns all records.
-spec read_file(string()) -> {ok, #pcap{}} | {error, term()}.
read_file(Filename) ->
    {ok, Header, Device} = open(Filename),
    {ok, Records} = read_records(Device),
    {ok, #pcap{header = Header, records = Records}}.

%% @doc Opens the file in read mode.
%% This function should be used together with next/1
-spec open(string()) -> {ok, #pcap_hdr{}, file:fd()} | {error, term()}.
open(Filename) ->
    case file:open(Filename, [read, binary]) of
        {ok, Device} ->
            {ok, Header} = read_header(Device),
            {ok, Header, Device};
        Error -> Error
    end.

%% @doc Opens the file in write mode and write the header.
%% The network type should be passed as second argument.
-spec open(string(), non_neg_integer() | atom()) -> ok | {error, term()}.
open(Filename, Network) when is_atom(Network) ->
    open(Filename, network(Network));
open(Filename, Network) when is_integer(Network) ->
    case file:open(Filename, [write, raw]) of
        {ok, Device} ->
            Major = 2,
            Minor = 4,
            GMT_to_localtime = 0,
            Sigfigs = 0,
            Data = <<?MAGIC:32, Major:16, Minor:16, GMT_to_localtime:32,
            Sigfigs:32, ?SNAPLEN:32, Network:32>>,
            ok = file:write(Device, Data),
            {ok, Device};
        Error -> Error
    end.

%% @doc Writes the new record with current timestamp.
-spec write(file:fd(), binary()) -> ok.
write(Device, Binary) ->
    {MegaSecs, Secs, _} = os:timestamp(),
    Timestamp = MegaSecs * 1000000 + Secs,
    write(Device, Timestamp, Binary).

%% @doc Writes the new record with specific timestamp.
-spec write(file:fd(), non_neg_integer(), binary()) -> ok.
write(Device, Timestamp, Binary) ->
    Len = byte_size(Binary),
    Timestamp_us = (Timestamp rem 1000) * 1000,
    Data = <<Timestamp:32, Timestamp_us:32, Len:32, Len:32, Binary/binary>>,
    file:write(Device, Data).

%% @doc Closes  the  file  referenced by Device.
-spec close(file:fd()) -> ok.
close(Device) ->
    ok = file:close(Device).

%% @doc Returns the next record.
%% This function should be used for sequence reading of records.
-spec next(file:fd()) -> {ok, #pcap_record{}} | eof | {error, term()}.
next(Device) ->
    read_record(Device).

%% Internal functions

%% @private
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

%% @private
-spec read_records(file:fd()) -> {ok, [#pcap_record{}]} | {error, term()}.
read_records(Device) ->
    read_records(Device, []).

%% @private
-spec read_records(file:fd(), list()) ->
    {ok, [#pcap_record{}]} | {error, term()}.
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

%% @private
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

%% @private
-spec is_truncated(non_neg_integer(), non_neg_integer()) -> boolean().
is_truncated(InclLen, OrigLen) -> InclLen < OrigLen.

%% @private
-spec network(atom()) -> non_neg_integer().
network(null) -> 0;
network(ethernet) -> 1;
network(mtp2) -> 140;
network(mtp3) -> 141;
network(sccp) -> 142;
network(ipv4) -> 228;
network(ipv6) -> 229.
