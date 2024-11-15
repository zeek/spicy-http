# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/http-post.pcap frameworks/files/hash-all-files %INPUT
# @TEST-EXEC: cat files.log | sed 's/SHA1,MD5/MD5,SHA1/g' >files.log.tmp && mv -f files.log.tmp files.log
#
# Drop fields which are incompatible between zeek-6.0 and dev version.
# @TEST-EXEC: zeek-cut -C ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration history <conn.log >conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: zeek-cut -C -n orig_fuids resp_fuids <http.log >http.log.tmp && mv http.log.tmp http.log
# @TEST-EXEC: zeek-cut -C -n fuid parent_fuid <files.log >files.log.tmp && mv files.log.tmp files.log
#
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff files.log
#
# @TEST-DOC: Test HTTP analyzer with small trace.

@load analyzer
