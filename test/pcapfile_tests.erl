-module(pcapfile_tests).

-include("pcapfile.hrl").
-include_lib("eunit/include/eunit.hrl").

read_file_test() ->
    {ok, PCAP} = pcapfile:read_file("../test/sctp.pcap"),
    Header = PCAP#pcap.header,
    ?assertEqual(Header#pcap_hdr.order, big),
    ?assertEqual(length(PCAP#pcap.records), 4).

open_test() ->
    {ok, Device} = pcapfile:open("test.pcap", 1),
    pcapfile:close(Device),
    {ok, PCAP} = pcapfile:read_file("test.pcap"),
    ?assertEqual({pcap_hdr,big,2,4,0,0,65535,1}, PCAP#pcap.header).

write_test() ->
    {ok, PCAP} = pcapfile:read_file("../test/sctp.pcap"),
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
