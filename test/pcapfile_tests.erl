-module(pcapfile_tests).

-include("pcapfile.hrl").
-include_lib("eunit/include/eunit.hrl").

read_file_test() ->
    {ok, PCAP} = pcapfile:read_file("../test/sctp.pcap"),
    Header = PCAP#pcap.header,
    ?assertEqual(Header#pcap_hdr.order, big),
    ?assertEqual(length(PCAP#pcap.records), 4).
