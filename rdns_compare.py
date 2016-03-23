#!/usr/bin/python

import os
import sys
import time
import numpy
import select
import socket
import urllib2
import argparse
import threading
import traceback
from collections import defaultdict,namedtuple

try:
    import dns.rcode as dc
    import dns.message as dm
    import dns.resolver as dr
    import dns.rdatatype as dt
except ImportError:
    sys.exit('Could not load the third party dependency "dnspython"')

class Service(object):
    def __init__(self, name):
        self.name = name
        self.recursives = []

class Recursive(object):
    Stats = namedtuple('Stats', ['mean', 'sd', 'sd_tail_mean', 'sd_tail_median', 'median', 'md', 'md_tail_mean', 'md_tail_median'])

    def __init__(self, address, service):
        self.address = address
        self.service = service
        self.rcodes = defaultdict(int)
        self._int_queries = self._ext_queries = 0
        self.sane = True
        self._min_time = float('inf')
        self.clean_cache = []
        self.prewarm_cache = []
        self._clean_cache_stats = self._prewarm_cache_stats = None

    @property
    def min_time(self):
        return self._min_time * 1000 # Convert from seconds to milliseconds

    @property
    def responses(self):
        return sum(self.rcodes.itervalues())

    @property
    def queries(self):
        """ Thread safe way of counting the number of queries sent:
            just keep track of the ones sent per thread separately. """
        return self._int_queries + self._ext_queries

    @property
    def loss(self):
        return float(self.responses) / self.queries if self.queries > 0 else 0

    @property
    def clean_stats(self):
        if not self._clean_cache_stats:
            self._clean_cache_stats = self._compute(self.clean_cache)
        return self._clean_cache_stats

    @property
    def prewarm_stats(self):
        if not self._prewarm_cache_stats:
            self._prewarm_cache_stats = self._compute(self.prewarm_cache)
        return self._prewarm_cache_stats

    def new_query(self):
        self._ext_queries += 1

    def _write_resp(self, dgram, rtime, ttype, csv):
        if csv:
            print >>csv, '%s,%s,%s,%s,%s,%.3f,%s,%d,%d,%s' % (self.service.name, self.address, \
                str(dgram.question[0].name), dt.to_text(dgram.question[0].rdtype), ttype, \
                rtime * 1000, dc.to_text(dgram.rcode()), len(dgram.answer), dgram.answer[0].ttl, \
                '|'.join([str(rd) for rd in self._get_rdata(dgram)]))

    def _get_rdata(self, dgram):
        try:
            return dgram.find_rrset(dgram.answer, dgram.question[0].name, dgram.question[0].rdclass, dgram.question[0].rdtype)
        except KeyError:
            return []

    def _compute(self, times):
        """ Compute statistics from all of the timing data collected """
        median = mean = sd = md = sd_tail_median = sd_tail_mean = md_tail_median = md_tail_mean = float('inf')
        times = [t * 1000 for t in times] # Convert from seconds to milliseconds
        if len(times) > 0:
            mean = numpy.mean(times)
            sd = numpy.std(times)

            tail = [v for v in times if v > mean + sd]
            if len(tail) > 0:
                sd_tail_mean = numpy.mean(tail)
                sd_tail_median = numpy.median(tail)

            median = numpy.median(times)
            md = numpy.median([abs(v - median) for v in times])
            tail = [v for v in times if v > median + md]
            if len(tail) > 0:
                md_tail_mean = numpy.mean(tail)
                md_tail_median = numpy.median(tail)
        return Recursive.Stats(mean, sd, sd_tail_mean, sd_tail_median, median, md, md_tail_mean, md_tail_median)

    def resp_sanity_1(self, dgram, data, rtime):
        csv,answers = data
        # Keep track of the minimum resolution time
        self._min_time = min(self._min_time, rtime)
        # See if we actually got an answer
        self.rcodes[dgram.rcode()] += 1
        # Test if the answers provided are within the sane answers
        found = False
        for rdata in self._get_rdata(dgram):
            if str(rdata) not in answers:
                self.sane = False
                print >>sys.stderr, '%s may be returning an incorrect response for %s' % (self.address, dgram.question[0])
                break
            found = True
        if not found:
            print >>sys.stderr, '%s did not return an answer for %s' % (self.address, dgram.question[0])

    def resp_popular_1(self, dgram, data, rtime):
        csv,probe = data
        # Keep track of the minimum resolution time
        self._min_time = min(self._min_time, rtime)
        # See if we actually got an answer
        self.rcodes[dgram.rcode()] += 1
        # If got an answer, keep track of time
        if dgram.rcode() == dc.NOERROR:
            self.clean_cache.append(rtime)
        # Send follow up query
        query = dm.make_query(dgram.question[0].name, dgram.question[0].rdtype, dgram.question[0].rdclass)
        probe.send(query, (self.address, 53), self.resp_popular_2, csv)
        self._int_queries += 1
        self._write_resp(dgram, rtime, 'clean', csv)

    def resp_popular_2(self, dgram, data, rtime):
        csv = data
        # Keep track of the minimum resolution time
        self._min_time = min(self._min_time, rtime)
        # See if we actually got an answer
        self.rcodes[dgram.rcode()] += 1
        # If got an answer AND it looks like it came from cache, keep track of time
        # A response looks like it came from cache if the TTL ends with a digit other than '0'
        if dgram.rcode() == dc.NOERROR and len(dgram.answer) > 0 and dgram.answer[0].ttl % 10 != 0:
            self.prewarm_cache.append(rtime)
        self._write_resp(dgram, rtime, 'prewarm', csv)

class Probe(object):
    def __init__(self, bind):
        self._socks = []
        self._ipv6_sock = None
        if socket.has_ipv6 and self.is_valid_ipv6_address(bind[0]):
            try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.settimeout(1)
                sock.bind(bind)
                self._ipv6_sock = sock
                self._socks.append(sock)
            except (AttributeError, socket.error):
                print >>sys.stderr, 'failed creating an IPv6 socket'
        self._ipv4_sock = None
        if self.is_valid_ipv4_address(bind[0]):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(1)
            sock.bind(bind)
            self._ipv4_sock = sock
            self._socks.append(sock)
        if len(self._socks) == 0:
            raise Exception('No sockets available to listen upon!')

        self._thread = threading.Thread(target = self._run)
        self._thread.daemon = True
        self._lock = threading.Lock()
        self._callbacks = {}
        self._running = False

    def is_valid_ipv4_address(self, address):
        if address == '':
            return True
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:  # no inet_pton
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return True
        except socket.error:
            return False
        return True

    def is_valid_ipv6_address(self, address):
        if address == '':
            return True
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error, AttributeError:
            return False
        return True

    def run(self):
        """ Begin listening on the socket for incoming datagrams """
        self._thread.start()

    def _run(self):
        self._running = True
        while self._running:
            try:
                read, _, _ = select.select(self._socks, [], [], 1)
                etime = time.time() # Response is wait, stop the clock
                for sock in read:
                    dgram, addr = sock.recvfrom(4096)
                    dgram = dm.from_wire(dgram)
                    # IPv6 will return additional details not needed for lookup
                    addr = (addr[0], addr[1])

                    key = self._key(dgram, addr)
                    with self._lock:
                        callback, data, stime = self._callbacks[key]
                        del self._callbacks[key]
                    callback(dgram, data, etime - stime)
            except socket.timeout:
                pass
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                print >>sys.stderr, 'Exception %s: %s' % (e, traceback.format_exc())
        self.running = False

    def _key(self, dgram, addr):
        return (dgram.id, str(dgram.question[0].name), addr)

    def close(self):
        if self._running:
            self._running = False
            self._thread.join()
            for sock in self._socks:
                sock.close()

    def send(self, dgram, addr, callback, data):
        key = self._key(dgram, addr)
        dgram = dgram.to_wire()
        if self._ipv4_sock and self.is_valid_ipv4_address(addr[0]):
            sock = self._ipv4_sock
        elif self._ipv6_sock and self.is_valid_ipv6_address(addr[0]):
            sock = self._ipv6_sock
        with self._lock:
            self._callbacks[key] = (callback, data, time.time())
        try:
            sock.sendto(dgram, addr)
        except socket.error:
            # This can happen for reasons including:
            # The interface supports IPv6 but doesn't actually have any routes
            pass

class Input(object):
    Sanity = namedtuple('Sanity', ['hostname', 'addresses'])
    POPULAR_DEFAULT_URL = 'https://kyle.schomp.info/data/popular.csv'
    SANITY_DEFAULT_URL = 'https://kyle.schomp.info/data/sanity.csv'
    RECURSIVES_DEFAULT_URL = 'https://kyle.schomp.info/data/recursives.csv'

    def __init__(self, popular = POPULAR_DEFAULT_URL, sanity = SANITY_DEFAULT_URL, recursives = RECURSIVES_DEFAULT_URL):
        if not popular:
            popular = Input.POPULAR_DEFAULT_URL
        if not sanity:
            sanity = Input.SANITY_DEFAULT_URL
        if not recursives:
            recursives = Input.RECURSIVES_DEFAULT_URL

        self.popular = list(self.filter_comments(urllib2.urlopen(popular)))

        self.sanity = []
        for line in self.filter_comments(urllib2.urlopen(sanity)):
            values = line.split(',')
            self.sanity.append(Input.Sanity(hostname = values[0], addresses = tuple(values[1:])))

        self.recursives = []
        for line in self.filter_comments(urllib2.urlopen(recursives)):
            values = line.split(',')
            service = Service(values[0])
            for value in values[1:]:
                service.recursives.append(Recursive(value, service))
            self.recursives.append(service)

    def filter_comments(self, src):
        for line in src:
            line = line.strip()
            if line == '' or line.strip().startswith('#'):
                continue
            yield line

def main(bind, source, output, csv, progress):
    """
        Run the tests.
        There are three stages:
        1) sanity check: confirm that the resolvers will actually answer queries
            and that the answers look legitimate.
        2) query for each name once to test response time with cache in 'real' state.
            Repeat query a second time to test response time with prewarmed cache.
        3) Compute statistics once all results fetched.
    """
    # Output detailed results to a csv file
    if csv:
        print >>csv, ','.join(('Provider', 'IP', 'Hostname', 'Type', 'Test', 'Duration', \
            'RCode', 'Num_Answers', 'TTL', 'Responses'))

    probe = Probe(bind)
    probe.run()

    # Test each of the sanity hostnames
    for i,sanity in enumerate(source.sanity):
        if progress:
            output.write('\rrunning sanity checks... ( {0} / {1} )'.format(i+1, len(source.sanity)))
            output.flush()
        for service in source.recursives:
            for recursive in service.recursives:
                query = dm.make_query(sanity.hostname, dt.A)
                probe.send(query, (recursive.address, 53), recursive.resp_sanity_1, (csv, sanity.addresses))
                recursive.new_query()
                time.sleep(0.01)
        time.sleep(0.1)
    time.sleep(1)
    # Send queries for each of the popular hostnames
    # A response to any of these queries will invoke a follow-up query
    for i,popular in enumerate(source.popular):
        if progress:
            output.write('\rrunning performance tests... ( {0} / {1} )'.format(i+1, len(source.popular)))
            output.flush()
        for service in source.recursives:
            for recursive in service.recursives:
                query = dm.make_query(popular, dt.A)
                probe.send(query, (recursive.address, 53), recursive.resp_popular_1, (csv, probe))
                recursive.new_query()
                time.sleep(0.01)
        time.sleep(0.1)
    time.sleep(2)

    probe.close()
    if progress:
        output.write('\r')
        output.flush()

    # Ignore resolvers that we never received responses from
    rdns = []
    for service in source.recursives:
        for recursive in service.recursives:
            if recursive.rcodes[dc.NOERROR] > 0:
                rdns.append(recursive)
            else:
                print >>sys.stderr, 'Received no answers from %s, dropping from consideration.' % (recursive.address)
    if len(rdns) == 0:
        print >>output, 'No RDNS to consider!'
        return

    # Formating output
    lines = []
    lines.append(['IP_Address', 'Provider', 'Mean', 'Median', 'SD', 'MD', 'Tail', 'Prewarm', 'Minimum', ''])
    lengths = [len(lines[0][i]) for i in range(len(lines[0]))]

    typical = sorted(rdns, key = lambda r: r.clean_stats.median)
    tail = sorted(rdns, key = lambda r: r.clean_stats.md_tail_mean)[0]
    shortest = sorted(rdns, key = lambda r: r.min_time)[0]
    prewarm = sorted(rdns, key = lambda r: r.prewarm_stats.median)[0]
    for r in typical:
        postfix = []
        if r == typical[0]:
            postfix.append('best typical performance')
        if r == tail:
            postfix.append('best tail performance')
        if r == shortest:
            postfix.append('fastest network path')
        if r == prewarm:
            postfix.append('best prewarmed performance')
        if len(postfix) > 0:
            postfix = '<-- ' + ', '.join(postfix)
        else:
            postfix = ''

        line = [r.address, r.service.name]
        line.extend(map(lambda v: format(v, '.3f'), [r.clean_stats.mean, r.clean_stats.median, r.clean_stats.sd, \
            r.clean_stats.md, r.clean_stats.md_tail_median, r.prewarm_stats.median, r.min_time]))
        line.append(postfix)
        lines.append(line)
        lengths = [max(lengths[i], len(line[i])) for i in range(len(lengths))]

    for line in lines:
        print >>output, '  '.join(['{:>{width}}'.format(v, width = w) for v,w in zip(line,lengths)]).rstrip()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description='Compare resolution performance of RDNS')
    parser.add_argument('-o', '--output', default=sys.stdout, type=argparse.FileType('w'), help='output file')
    parser.add_argument('-c', '--csv', default=None, type=argparse.FileType('w'), help='csv output file for detailed results')
    parser.add_argument('-b', '--bind', default=':0', help='binding interface')
    parser.add_argument('-n', '--names', default=1000, type=int, help='number of hostnames to use in testing')
    parser.add_argument('-s', '--sanity', default=None, help='override url for the sanity list of hostnames')
    parser.add_argument('-p', '--popular', default=None, help='override url for the popular list of hostnames')
    parser.add_argument('-r', '--recursives', default=None, help='override url for the list of recursive dns servers')
    parser.add_argument('-a', '--additional', nargs='+', default=[], help='IP addresses of additional recursive resolvers')
    parser.add_argument('-i', '--inuse', action='store_true', default=False, help='include the system configured recursive resolver')
    parser.add_argument('--progress', action='store_true', default=False, help='report progress updates')
    args = parser.parse_args()

    hostname,port = args.bind.split(':')
    bind = (hostname, int(port))

    source = Input(args.popular, args.sanity, args.recursives)
    for additional in args.additional:
        service = Service(additional)
        service.recursives.append(Recursive(additional, service))
        source.recursives.append(service)
    if args.inuse:
        service = Service('inuse')
        for nameserver in dr.get_default_resolver().nameservers:
            service.recursives.append(Recursive(nameserver, service))
        source.recursives.append(service)
    source.popular = source.popular[:args.names]

    main(bind, source, args.output, args.csv, args.progress)
