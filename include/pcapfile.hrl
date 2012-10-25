%%% http://wiki.wireshark.org/Development/LibpcapFileFormat

-define(MAGIC, 16#a1b2c3d4).

-define(PCAP_HEADER_LITTLE,
    ?MAGIC:4/little-unsigned-integer-unit:8,
    Major:2/little-unsigned-integer-unit:8,
    Minor:2/little-unsigned-integer-unit:8,
    GMT_to_localtime:4/little-unsigned-integer-unit:8,
    Sigfigs:4/little-unsigned-integer-unit:8,
    Snaplen:4/little-unsigned-integer-unit:8,
    Network:4/little-unsigned-integer-unit:8).

-define(PCAP_HEADER_BIG,
    ?MAGIC:4/big-unsigned-integer-unit:8,
    Major:2/big-unsigned-integer-unit:8,
    Minor:2/big-unsigned-integer-unit:8,
    GMT_to_localtime:4/big-unsigned-integer-unit:8,
    Sigfigs:4/big-unsigned-integer-unit:8,
    Snaplen:4/big-unsigned-integer-unit:8,
    Network:4/big-unsigned-integer-unit:8).

-define(PCAP_RECORD_LITTLE,
    Timestamp_s:4/little-unsigned-integer-unit:8,
    Timestamp_us:4/little-unsigned-integer-unit:8,
    InclLen:4/little-unsigned-integer-unit:8,
    OrigLen:4/little-unsigned-integer-unit:8,
    Payload:InclLen/binary-unit:8).

-define(PCAP_RECORD_BIG,
    Timestamp_s:4/big-unsigned-integer-unit:8,
    Timestamp_us:4/big-unsigned-integer-unit:8,
    InclLen:4/big-unsigned-integer-unit:8,
    OrigLen:4/big-unsigned-integer-unit:8,
    Payload:InclLen/binary-unit:8).

-record(pcap_hdr, {
    order :: little | big,
    major :: non_neg_integer(),
    minor :: non_neg_integer(),
    gmt_to_localtime :: non_neg_integer(),
    sigfigs :: non_neg_integer(),
    snaplen :: non_neg_integer(),
    network :: non_neg_integer()
}).

-record(pcap_record, {
    seq :: non_neg_integer(),
    timestamp_s :: non_neg_integer(),
    timestamp_us :: non_neg_integer(),
    incl_len :: non_neg_integer(),
    orig_len :: non_neg_integer(),
    truncated :: boolean(),
    payload :: binary()
}).

-record(pcap, {header :: #pcap_hdr{}, records :: [#pcap_record{}]}).
