# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/http-post.pcap frameworks/files/hash-all-files %INPUT
# @TEST-EXEC: cat files.log | sed 's/SHA1,MD5/MD5,SHA1/g' >files.log.tmp && mv -f files.log.tmp files.log
# @TEST-EXEC: zeek-cut -C ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service history <conn.log >conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: zeek-cut -C fuid source depth analyzers mime_type filename total_bytes <files.log >files.log.tmp && mv files.log.tmp files.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff files.log
#
# @TEST-DOC: Test HTTP analyzer with small trace.

@load analyzer
