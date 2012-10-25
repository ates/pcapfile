-module(pcapfile).

%% API
-export([read_file/1]).

-include("pcapfile.hrl").

-spec read_file(string()) -> {ok, #pcap{}} | {error, term()}.
read_file(Filename) ->
    case file:read_file(Filename) of
        {ok, Binary} ->
            decode(Binary);
        {error, Reason} ->
            {error, Reason}
    end.

%% Internal functions

-spec decode(binary()) -> {ok, #pcap{}} | {error, term()}.
decode(<<?PCAP_HEADER_LITTLE, Rest/binary>>) ->
    Header = #pcap_hdr{
        order = little,
        major = Major,
        minor = Minor,
        gmt_to_localtime = GMT_to_localtime,
        sigfigs = Sigfigs,
        snaplen = Snaplen,
        network = Network
    },
    Records = decode_records(little, Rest),
    {ok, #pcap{header = Header, records = Records}};
decode(<<?PCAP_HEADER_BIG, Rest/binary>>) ->
    Header = #pcap_hdr{
        order = big,
        major = Major,
        minor = Minor,
        gmt_to_localtime = GMT_to_localtime,
        sigfigs = Sigfigs,
        snaplen = Snaplen,
        network = Network
    },
    Records = decode_records(big, Rest),
    {ok, #pcap{header = Header, records = Records}}.

-spec decode_records(little | big, binary()) -> [#pcap_record{}].
decode_records(Order, Binary) ->
    decode_records(Order, Binary, 1, []).

-spec decode_records(little | big, binary(), pos_integer(), list()) ->
    [#pcap_record{}].
decode_records(_Order, <<>>, _Seq, Acc) ->
    lists:reverse(Acc);
decode_records(little, <<?PCAP_RECORD_LITTLE, Rest/binary>>, Seq, Acc) ->
    Record = #pcap_record{
        seq = Seq,
        timestamp_s = Timestamp_s,
        timestamp_us = Timestamp_us,
        incl_len = InclLen,
        orig_len = OrigLen,
        truncated = is_truncated(InclLen, OrigLen),
        payload = Payload
    },
    decode_records(little, Rest, Seq + 1, [Record | Acc]);
decode_records(big, <<?PCAP_RECORD_BIG, Rest/binary>>, Seq, Acc) ->
    Record = #pcap_record{
        seq = Seq,
        timestamp_s = Timestamp_s,
        timestamp_us = Timestamp_us,
        incl_len = InclLen,
        orig_len = OrigLen,
        truncated = is_truncated(InclLen, OrigLen),
        payload = Payload
    },
    decode_records(big, Rest, Seq + 1, [Record | Acc]).

-spec is_truncated(non_neg_integer(), non_neg_integer()) -> boolean().
is_truncated(InclLen, OrigLen) -> InclLen < OrigLen.
