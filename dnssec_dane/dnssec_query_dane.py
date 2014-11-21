################################################################################
#                                                                              #
# Copyright (C) 2011-2014, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

# Portions of the code come from
# https://github.com/getdnsapi/getdns-python-bindings and are licensed as such.
#Copyright (c) 2014, Verisign, Inc., NLnet Labs
#All rights reserved.
#Redistribution and use in source and binary forms, with or without
#modification, are permitted provided that the following conditions are met:
#* Redistributions of source code must retain the above copyright
#notice, this list of conditions and the following disclaimer.
#* Redistributions in binary form must reproduce the above copyright
#notice, this list of conditions and the following disclaimer in the
#documentation and/or other materials provided with the distribution.
#* Neither the names of the copyright holders nor the
#names of its contributors may be used to endorse or promote products
#derived from this software without specific prior written permission.
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
#DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import sys, socket, hashlib
import getdns
sys.path.append("..")
from armoryengine.ArmoryUtils import binary_to_hex

# Proof-of-concept code that contacts a server, grabs TLSA records, and prints
# out the results.

# Print the "RDATA" contents of a TLSA resource record (RR).
def get_tlsa_rdata_set(replies):
    tlsa_rdata_set = []
    print 'Data from TLSA replies'
    for reply in replies:
        for rr in reply['answer']:
            if rr['type'] == getdns.GETDNS_RRTYPE_TLSA:
                rdata = rr['rdata']
                usage = rdata['certificate_usage']
                print 'usage: %d' % usage
                selector = rdata['selector']
                print 'selector: %d' % selector
                matching_type = rdata['matching_type']
                print 'matching_type: %d' % matching_type
                cadata = rdata['certificate_association_data']
                print 'cadata: %s' % binary_to_hex(str(cadata))
                tlsa_rdata_set.append(
                    (usage, selector, matching_type, cadata) )
    return tlsa_rdata_set


# Get a TLSA record from a given host/port.
def get_tlsa(port, proto, hostname):
    qname = "_%d._%s.%s" % (port, proto, hostname)
    ctx = getdns.Context()
    extensions = { "dnssec_return_only_secure": getdns.GETDNS_EXTENSION_TRUE }
    results = ctx.general(name=qname,
                          request_type=getdns.GETDNS_RRTYPE_TLSA,
                          extensions=extensions)
    status = results['status']

    if status == getdns.GETDNS_RESPSTATUS_GOOD:
        return get_tlsa_rdata_set(results['replies_tree'])
    else:
        print "getdns: failed looking up TLSA record, code: %d" % status
        return None


# For now, the code is dead simple. Pass in a hostname/port where TLSA records
# will be queried. Our code will just print out the raw record info.
if __name__ == '__main__':
    hostname, port = sys.argv[1:]
    port = int(port)
    tlsa_rdata_set = get_tlsa(port, "tcp", hostname)
