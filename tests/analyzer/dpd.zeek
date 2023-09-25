# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -Cr ${TRACES}/http-non-default-port.pcap %INPUT
# @TEST-EXEC: zeek-cut -C ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service history <conn.log >conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: mv http.log http.log.bak && zeek-cut -n host <http.log.bak >http.log && btest-diff http.log
#
# @TEST-DOC: Test that DPD triggers the HTTP analyzer with communication on non-default port.

@load analyzer
