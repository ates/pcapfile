-module(pcapfile_tests).

-include("pcapfile.hrl").
-include_lib("eunit/include/eunit.hrl").

read_file_test() ->
    {ok, PCAP} = pcapfile:read_file("test/sctp.pcap"),
    Header = PCAP#pcap.header,
    ?assertEqual(Header#pcap_hdr.order, big),
    ?assertEqual(length(PCAP#pcap.records), 4).

open_test() ->
    Networks = [null, ethernet, mtp2, mtp3, sccp, ipv4, ipv6],
    {ok, Device} = pcapfile:open("test.pcap", 1),
    pcapfile:close(Device),
    {ok, PCAP} = pcapfile:read_file("test.pcap"),
    ?assertEqual({pcap_hdr,big,2,4,0,0,65535,1}, PCAP#pcap.header),
    ?assertEqual({error, enoent}, pcapfile:open("nofile.pcap")),
    ?assertEqual({error, enoent}, pcapfile:open("/nonfolder/nofile.pcap", 1)),
    [{ok, _} = pcapfile:open(atom_to_list(T) ++ ".pcap", T) || T <- Networks].

write_test() ->
    {ok, PCAP} = pcapfile:read_file("test/sctp.pcap"),
    {ok, Device} = pcapfile:open("test.pcap", PCAP#pcap.header#pcap_hdr.network),
    F = fun(Record) ->
            TS = Record#pcap_record.timestamp_s,
            Binary = Record#pcap_record.payload,
            pcapfile:write(Device, TS, Binary)
    end,
    lists:foreach(F, PCAP#pcap.records),
    pcapfile:close(Device),
    {ok, PCAP1} = pcapfile:read_file("test.pcap"),
    ?assertEqual(PCAP#pcap.header, PCAP1#pcap.header),
    ?assertEqual(length(PCAP#pcap.records), length(PCAP1#pcap.records)).

next_test() ->
    {ok, _H, Device} = pcapfile:open("test/sctp.pcap"),
    {ok, Record} = pcapfile:next(Device),
    pcapfile:close(Device),
    ?assertEqual(Record#pcap_record.timestamp_s, 1088696689).
