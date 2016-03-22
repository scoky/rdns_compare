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
import dnslib as dl
import dns.resolver
from collections import defaultdict,namedtuple

class Service(object):
    def __init__(self, name):
        self.name = name
        self.recursives = []

class Recursive(object):
    def __init__(self, address, service):
        self.address = address
        self.service = service
        self.rcodes = defaultdict(int)
        self._int_queries = self._ext_queries = 0
        self.sane = True
        self.min_time = float('inf')
        self.clean_cache = []
        self.prewarm_cache = []
    
    @property
    def responses(self):
        return sum(self.rcodes.itervalues())

    @property
    def queries(self):
        """ Thread safe way of counting the number of queries sent:
            just keep track of the ones sent per thread separately. """
        return self._int_queries + self._ext_queries

    def incQueries(self):
        self._ext_queries += 1

    def _write_resp(self, dgram, rtime, ttype, csv):
        if csv:
            print >>csv, '%s,%s,%s,%s,%s,%.3f,%s,%d,%d,%s' % (self.service.name, self.address, str(dgram.q.qname), \
                dl.QTYPE[dgram.q.qtype], ttype, rtime, dl.RCODE[dgram.header.rcode], len(dgram.rr), dgram.a.ttl, \
                '|'.join([str(r.rdata) for r in dgram.rr]))

    def compute(self):
        """ Compute statistics from all of the timing data collected """
        if len(self.clean_cache) > 0:
            self.clean_cache_median = numpy.median(self.clean_cache)
            self.clean_cache_mean = numpy.mean(self.clean_cache)
            self.clean_cache_sd = numpy.std(self.clean_cache)
            self.clean_cache_md = numpy.median([abs(v - self.clean_cache_median) for v in self.clean_cache])
            
            tail = [v for v in self.clean_cache if v > self.clean_cache_mean + self.clean_cache_sd]
            if len(tail) > 0:
                self.clean_cache_tail_sd = numpy.mean(tail)
            else:
                self.clean_cache_tail_sd = float('inf')
                
            tail = [v for v in self.clean_cache if v > self.clean_cache_median + self.clean_cache_md]
            if len(tail) > 0:
                self.clean_cache_tail_md = numpy.mean(tail)
            else:
                self.clean_cache_tail_md = float('inf')
        else:
            self.clean_cache_median = self.clean_cache_mean = self.clean_cache_sd = self.clean_cache_md = \
                self.clean_cache_tail_sd = self.clean_cache_tail_md = float('inf')

        if len(self.prewarm_cache) > 0:
            self.prewarm_cache_median = numpy.median(self.prewarm_cache)
            self.prewarm_cache_mean = numpy.mean(self.prewarm_cache)
            self.prewarm_cache_sd = numpy.std(self.prewarm_cache)
            self.prewarm_cache_md = numpy.median([abs(v - self.prewarm_cache_median) for v in self.prewarm_cache])
            
            tail = [v for v in self.prewarm_cache if v > self.prewarm_cache_mean + self.prewarm_cache_sd]
            if len(tail) > 0:
                self.prewarm_cache_tail_sd = numpy.mean(tail)
            else:
                self.prewarm_cache_tail_sd = float('inf')
                
            tail = [v for v in self.prewarm_cache if v > self.prewarm_cache_median + self.prewarm_cache_md]
            if len(tail) > 0:
                self.prewarm_cache_tail_md = numpy.mean(tail)
            else:
                self.prearm_cache_tail_md = float('inf')
        else:
            self.prewarm_cache_median = self.prewarm_cache_mean = self.prewarm_cache_sd = \
                self.prewarm_cache_md = self.prewarm_cache_tail_sd = self.prewarm_cache_tail_md = float('inf')

    def resp_sanity_1(self, dgram, data, rtime):
        csv,answers = data
        # Keep track of the minimum resolution time
        self.min_time = min(self.min_time, rtime)
        # See if we actually got an answer
        self.rcodes[dgram.header.rcode] += 1
        # Test if the answers provided are within the sane answers
        for record in dgram.rr:
            if str(record.rdata) not in answers:
                self.sane = False
                print >>sys.stderr, '%s may be returning an incorrect response for %s' % (self.address, dgram.q)
                break
        #self._write_resp(dgram, rtime, csv) # Do NOT write sanity checks to output

    def resp_popular_1(self, dgram, data, rtime):
        csv,probe = data
        # Keep track of the minimum resolution time
        self.min_time = min(self.min_time, rtime)
        # See if we actually got an answer
        self.rcodes[dgram.header.rcode] += 1
        # If got an answer, keep track of time
        if dgram.header.rcode == dl.RCODE.NOERROR:
            self.clean_cache.append(rtime)
        # Send follow up query
        query = dl.DNSRecord.question(dgram.q.qname)
        probe.send(query, (self.address, 53), self.resp_popular_2, csv)
        self._int_queries += 1
        self._write_resp(dgram, rtime, 'clean', csv)

    def resp_popular_2(self, dgram, data, rtime):
        csv = data
        # Keep track of the minimum resolution time
        self.min_time = min(self.min_time, rtime)
        # See if we actually got an answer
        self.rcodes[dgram.header.rcode] += 1
        # If got an answer AND it looks like it came from cache, keep track of time
        # A response looks like it came from cache if the TTL ends with a digit other than '0'
        if dgram.header.rcode == dl.RCODE.NOERROR and len(dgram.rr) > 0 and dgram.rr[0].ttl % 10 != 0:
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
                for sock in read:
                    dgram, addr = sock.recvfrom(4096)
                    dgram = dl.DNSRecord.parse(dgram)
                    etime = time.time()
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
        return (dgram.header.id, str(dgram.q.qname), addr)

    def close(self):
        if self._running:
            self._running = False
            for sock in self._socks:
                sock.close()
            self._thread.join()

    def send(self, dgram, addr, callback, data):
        key = self._key(dgram, addr)
        with self._lock:
            self._callbacks[key] = (callback, data, time.time())
        try:
            if self._ipv4_sock and self.is_valid_ipv4_address(addr[0]):
                self._ipv4_sock.sendto(dgram.pack(), addr)
            elif self._ipv6_sock and self.is_valid_ipv6_address(addr[0]):
                self._ipv6_sock.sendto(dgram.pack(), addr)
        except socker.error:
            # This can happen for reasons including:
            # The interface supports IPv6 but doesn't actually have any routes
            # The socket has been closed already. Could lock, but probably not worth putting a socket call in lock
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
                query = dl.DNSRecord.question(sanity.hostname)
                probe.send(query, (recursive.address, 53), recursive.resp_sanity_1, (csv, sanity.addresses))
                recursive.incQueries()
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
                query = dl.DNSRecord.question(popular)
                probe.send(query, (recursive.address, 53), recursive.resp_popular_1, (csv, probe))
                recursive.incQueries()
                time.sleep(0.01)
        time.sleep(0.1)
    time.sleep(2)
    
    probe.close()
    if progress:
        output.write('\r')
        output.flush()

    # Compute stats
    rdns = []
    for service in source.recursives:
        for recursive in service.recursives:
            if recursive.rcodes[dl.RCODE.NOERROR] > 0:
                recursive.compute()
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

    typical = sorted(rdns, key = lambda r: r.clean_cache_median)
    tail = sorted(rdns, key = lambda r: r.clean_cache_tail_md)[0]
    shortest = sorted(rdns, key = lambda r: r.min_time)[0]
    prewarm = sorted(rdns, key = lambda r: r.prewarm_cache_median)[0]
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
        line.extend(map(lambda v: format(v, '.3f'), [r.clean_cache_mean, r.clean_cache_median, r.clean_cache_sd, \
            r.clean_cache_md, r.clean_cache_tail_md, r.prewarm_cache_median, r.min_time]))
        line.append(postfix)
        lines.append(line)
        lengths = [max(lengths[i], len(line[i])) for i in range(len(lengths))]
        
    for line in lines:
        print >>output, '  '.join(['{:<{width}}'.format(v, width = w) for v,w in zip(line,lengths)]).rstrip()

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
        for nameserver in dns.resolver.get_default_resolver().nameservers:
            service.recursives.append(Recursive(nameserver, service))
        source.recursives.append(service)
    source.popular = source.popular[:args.names]

    main(bind, source, args.output, args.csv, args.progress)

