# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/http-post.pcap frameworks/files/hash-all-files %INPUT
# @TEST-EXEC: cat files.log | sed 's/SHA1,MD5/MD5,SHA1/g' >files.log.tmp && mv -f files.log.tmp files.log
# @TEST-EXEC: zeek-cut -C ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service history <conn.log >conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: zeek-cut -C fuid source depth analyzers mime_type filename total_bytes <files.log >files.log.tmp && mv files.log.tmp files.log
# @TEST-EXEC: btest-diff conn.log
# Skip baselining of fuids on pre-6.0 versions (fuids stopped being canonified with 6.0).
# @TEST-EXEC: zeek -b -e 'exit(Version::at_least("6.0") ? 1 : 0)' || btest-diff http.log
# @TEST-EXEC: zeek -b -e 'exit(Version::at_least("6.0") ? 1 : 0)' || btest-diff files.log
#
# @TEST-DOC: Test HTTP analyzer with small trace.

@load analyzer
