#include <stdio.h>
#include <resolv.h>
#include <memory.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <map>
#include <vector>
#include <list>
#include <set>
#include <string>
#include <algorithm>
#include "config.h"

#define RESPONSE_MAX_ANSWER_RR		32
#define QUESTION_MAX_REQUEST		32

struct statistic_enrty {
	unsigned int rx_query;
	unsigned int tx_query;
	unsigned int query_retry;
	unsigned int rx_response;
	unsigned int rx_response_accepted;
	unsigned int tx_response;
	unsigned int total_request;
	unsigned int request_timeout;
	unsigned int cache_added;
	unsigned int cache_replaced;
	unsigned int cache_timeout;
	unsigned int cache_refresh;
	unsigned int cache_max;
};

bool operator<(const sockaddr_in& a, const sockaddr_in& b) {
	return a.sin_addr.s_addr < b.sin_addr.s_addr;
};

bool operator<(const timespec& a, const timespec& b) {
	if (a.tv_sec != b.tv_sec) return a.tv_sec < b.tv_sec;
	return a.tv_nsec < b.tv_nsec;
};

struct ns_list {
	std::string scope;
	std::map<sockaddr_in, unsigned short> addrs;
};

struct question_entry {
	std::string qname;
	unsigned short qtype;
	unsigned short qclass;
	bool operator <(const question_entry& rhs) const {
		if (qtype != rhs.qtype) return qtype < rhs.qtype;
		if (qclass != rhs.qclass) return qclass < rhs.qclass;
		if (qname.size() != rhs.qname.size()) return qname.size() < rhs.qname.size();
		return qname.compare(rhs.qname) < 0;
	}
	bool operator ==(const question_entry& rhs) const {
		if (qtype != rhs.qtype) return false;
		if (qclass != rhs.qclass) return false;
		if (qname.size() != rhs.qname.size()) return false;
		return qname.compare(rhs.qname) == 0;
	}
	bool operator !=(const question_entry& rhs) const {
		return !(*this == rhs);
	}
};

struct resource_entry {
	question_entry rq;
	time_t rexpiry;
	std::string rdata;
	unsigned short rperf; // for MX record
};

struct cache_entry {
	question_entry question;
	time_t last_update;
	time_t last_use;
	time_t least_expiry;
	std::list<resource_entry> rrs;
};

struct remote_source {
	sockaddr_in addr;
	unsigned short id;	// id of original request
};

struct local_source {
	question_entry oq;
	unsigned int progress;	// progress of original request
	unsigned int base_progress;
	bool need_answer;
};

struct request_entry {
	question_entry question;
	question_entry nq;
	ns_list ns;
	unsigned int progress;
	time_t rexpiry;
	timespec lastsend;
	unsigned int retry;
	std::vector<resource_entry> anrr;
	std::list<remote_source> rlist;
	std::map<question_entry, local_source> llist;
	bool use_cache;
};

std::map<question_entry, cache_entry> cache_map;
std::map<time_t, std::set<cache_entry*> > cache_expiry_map;
std::map<question_entry, request_entry> request_map;
std::map<time_t, std::set<request_entry*> > request_expiry_map;
std::map<timespec, std::set<request_entry*> > query_expiry_map;


unsigned char sendbuf[NS_PACKETSZ];
unsigned char *pspos = sendbuf;
unsigned char *psend = sendbuf+sizeof(sendbuf);
unsigned char recvbuf[NS_PACKETSZ];
statistic_enrty ss;
ns_list root_addrs;
char *remote_addr = NULL;
int lfd = -1;
int rfd = -1;
timespec now = {0,0};
// options
in_addr bind_address = { INADDR_ANY };
unsigned short bind_port = 53;
std::vector<std::string> custom_root;
time_t cache_update_ttl = 180;
time_t cache_update_interval = 60;
time_t cache_update_min_ttl = 900;
unsigned int cache_soft_watermark = 50000;
time_t cache_soft_lru = 604800; // 7 days
unsigned int cache_hard_watermark = 100000;
unsigned int request_timeout = 5;
unsigned int query_timeout = 500;
unsigned int query_retry = 3;
bool verbose = false;

void print_help();
timespec timespec_add(const timespec& a, int ms);
long long timespec_diff(const timespec& a, const timespec& b); // return milliseconds
bool create_socket(int& fd, sockaddr_in* addr);
void init_root();
void handle_signal(int signal);
bool add_response_cache_entry(ns_msg& handle, ns_rr& rr, const std::string& scope, std::map<question_entry, cache_entry>& entries, unsigned short& rrtype);
void handle_response(ns_msg& handle, const sockaddr_in& addr);
bool add_request(const question_entry& question, const question_entry* oq, unsigned int progress, const sockaddr_in *addr, unsigned short id,  bool need_answer, bool use_cache, request_entry*& pentry);
void handle_request(ns_msg& handle, const sockaddr_in& addr);
void handle_packet(const unsigned char* buf, int size, sockaddr_in& addr, bool local);
void build_packet(bool query, bool no_domain, const question_entry& question, const std::vector<resource_entry>* anrr, unsigned short adrrc);
void send_packet(const sockaddr_in& addr, unsigned short id, bool local);
bool get_answer(question_entry& question, std::vector<resource_entry>& rr, bool use_cache);
unsigned short add_additional_answer(std::vector<resource_entry>& rr);
void find_nameserver(const question_entry& question, ns_list& ns, std::set<std::string>& ns_with_no_addr);
void update_request_lastsend(request_entry& request, bool retry, bool delete_only);
bool try_complete_request(request_entry& request, bool no_more_data, bool no_domain, unsigned int progress);
void check_expiry();
bool parse_option(int argc, char **argv);

void print_help() {
	printf(
		"Usage: fastdns [-b address] [-p port] [-r server ...] [-t ttl] [-i interval]\n"
		"       [-n min] [-s soft] [-l lru] [-d hard] [-o timeout] [-q timeout]\n"
		"       [-y retry] [-v] [-h]\n"
		"\n"
		"Recursive DNS server\n"
		"\n"
		"    -b address      address to listen, default: 0.0.0.0\n"
		"    -p port         port to listen, default: 53\n"
		"    -r server       root server address, can be specified multiple times\n"
		"                    if set to other recursive DNS servers(eg: 8.8.8.8 and/or\n"
		"                    8.8.4.4), fastdns will act like a forwarding DNS server\n"
		"                    if not specified, a built-in list will be used\n"
		"    -t ttl          when cache entry have less then ttl seconds left before\n"
		"                    expiry, fastdns will refresh that entry by sending a query\n"
		"                    to corresponding nameserver, default: 180\n"
		"    -i interval     cache refresh interval, default: 60\n"
		"    -n min          cache entry will not get refreshed unless it's original ttl\n"
		"                    is larger then this value, default: 900\n"
		"    -s soft         when cache size is above soft watermark, cache entry will\n"
		"                    not get refreshed unless it has been recently used, or it's\n"
		"                    a NS record or corresponding A record, default: 50000\n"
		"    -l lru          cache entry which used in last lru seconds will be\n"
		"                    considered as recently used, default: 604800 (7 days)\n"
		"    -d hard         when cache size is above hard watermark, only NS record and\n"
		"                    corresponding A record will get refreshed, default: 100000\n"
		"    -o timeout      request timeout, default: 5\n"
		"    -q timeout      query timeout in millisecond, fastdns will resend query to\n"
		"                    nameserver if no response received, default: 500\n"
		"    -y retry        query retry count when timeout, default: 3\n"
		"    -v              verbose\n"
		"    -h              show this message\n"
	);
}

void handle_signal(int signal) {
	syslog(LOG_INFO, "--- Statistics ---");
	syslog(LOG_INFO, "Query received    : %d", ss.rx_query);
	syslog(LOG_INFO, "Query send        : %d", ss.tx_query);
	syslog(LOG_INFO, "Query retry       : %d", ss.query_retry);
	syslog(LOG_INFO, "Response received : %d", ss.rx_response);
	syslog(LOG_INFO, "Response accepted : %d", ss.rx_response_accepted);
	syslog(LOG_INFO, "Response send     : %d", ss.tx_response);
	syslog(LOG_INFO, "Total request     : %d", ss.total_request);
	syslog(LOG_INFO, "Request timeout   : %d", ss.request_timeout);
	syslog(LOG_INFO, "Cache added       : %d", ss.cache_added);
	syslog(LOG_INFO, "Cache replaced    : %d", ss.cache_replaced);
	syslog(LOG_INFO, "Cache timeout     : %d", ss.cache_timeout);
	syslog(LOG_INFO, "Cache refresh     : %d", ss.cache_refresh);
	syslog(LOG_INFO, "Max cache size    : %d", ss.cache_max);
	syslog(LOG_INFO, "--- Status ---");
	syslog(LOG_INFO, "Current cache size: %d", (int)cache_map.size());
	syslog(LOG_INFO, "Pending request   : %d", (int)request_map.size());
}

int main(int argc, char **argv) {
	if (parse_option(argc, argv) == false) return -1;
	openlog("fastdns", LOG_PID|LOG_CONS, LOG_USER);
	srand(time(0));
	memset(&ss, 0, sizeof(ss));
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = bind_address;
	addr.sin_port = htons(bind_port);
	if (create_socket(lfd, &addr) == false) return -1;
	if (create_socket(rfd, NULL) == false) return -1;
	init_root();
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &handle_signal;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		syslog(LOG_ERR, "Failed to setup signal handler!");
		return -1;
	}
	
	fd_set readfds, errorfds;
	int maxfd = std::max(lfd, rfd) + 1;
	timespec last_check = {0,0};
	while (true) {
		FD_ZERO(&readfds);
		FD_ZERO(&errorfds);
		FD_SET(lfd, &readfds);
		FD_SET(rfd, &readfds);
		FD_SET(lfd, &errorfds);
		FD_SET(rfd, &errorfds);
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 50 * 1000;
		if (select(maxfd, &readfds, NULL, &errorfds, &tv) < 0) {
			if (errno == EINTR) continue;
			syslog(LOG_ERR, "select encountered an error %d!", errno);
			return -1;
		}
		if (FD_ISSET(lfd, &errorfds) || FD_ISSET(rfd, &errorfds)) {
			syslog(LOG_ERR, "socket error!");
			return -1;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
			syslog(LOG_ERR, "clock_gettime encountered an error %d!", errno);
			return -1;
		}
		if (FD_ISSET(lfd, &readfds) || FD_ISSET(rfd, &readfds)) {
			socklen_t addr_len = sizeof(addr);
			int rc=recvfrom(FD_ISSET(lfd, &readfds) ? lfd : rfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&addr, &addr_len);
			if (rc == 0) break;
			else if (rc > 0) {
				remote_addr = inet_ntoa(addr.sin_addr);
				handle_packet(recvbuf, rc, addr, FD_ISSET(lfd, &readfds));
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				syslog(LOG_ERR, "recvfrom encountered an error %d!", errno);
				return -1;
			}
		}
		if (timespec_diff(now ,last_check) >= 50) {
			check_expiry();
			last_check = now;
		}
	}
	syslog(LOG_INFO, "exit...");
	return 0;
}

timespec timespec_add(const timespec& a, int ms) {
	timespec result = a;
	result.tv_sec += ms/1000;
	result.tv_nsec += (ms%1000) * 1000000;
	int carry = 0;
	int nsec = 1000*1000000;
	if (result.tv_nsec < 0) carry = -1;
	else if (result.tv_nsec >= nsec) carry = 1;
	result.tv_sec += carry;
	result.tv_nsec -= carry * nsec;
	return result;
}

long long timespec_diff(const timespec& a, const timespec& b) {
	long long result = 0;
	if (a.tv_sec > b.tv_sec) result += (a.tv_sec - b.tv_sec) * 1000;
	else result -= (b.tv_sec - a.tv_sec) * 1000;
	result += a.tv_nsec/1000000;
	result -= b.tv_nsec/1000000;
	return result;
}

bool create_socket(int& fd, sockaddr_in* addr) {
	fd = socket(AF_INET , SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		syslog(LOG_ERR, "Can't create udp socket!");
		return false;
	}
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		syslog(LOG_ERR, "fcntl get flags failed!");
		return false;
	}
	if (fcntl(fd, F_SETFL, flags |= O_NONBLOCK) < 0) {
		syslog(LOG_ERR, "fcntl set flags failed!");
		return false;
	}
	if (addr && bind(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
		syslog(LOG_ERR, "bind on port %d failed!", ntohs(addr->sin_port));
		return false;
	}
	return true;
}

void init_root() {
	root_addrs.scope = "";
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53);
	for (size_t i = 0; i < custom_root.size(); i++) {
		if (inet_aton(custom_root[i].c_str(), &addr.sin_addr) == 0) continue;
		root_addrs.addrs.insert(std::make_pair(addr, 0));
	}
	if (root_addrs.addrs.size() != 0) return;
	custom_root.clear();
	addr.sin_addr.s_addr = htonl(0xC6290004);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC0E44FC9);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC021040C);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC7075B0D);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC0CBE60A);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC00505F1);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC0702404);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0x803F0235);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC0249411);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC03A801E);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC1000E81);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xC707532A);	root_addrs.addrs.insert(std::make_pair(addr, 0));
	addr.sin_addr.s_addr = htonl(0xCA0C1B21);	root_addrs.addrs.insert(std::make_pair(addr, 0));
}

bool add_response_cache_entry(ns_msg& handle, ns_rr& rr, const std::string& scope, std::map<question_entry, cache_entry>& entries, unsigned short& rrtype) {
	char domain_name[MAXDNAME];
	resource_entry r;
	r.rq.qname = ns_rr_name(rr);
	r.rq.qtype = rrtype = ns_rr_type(rr);
	r.rq.qclass = ns_rr_class(rr);
	r.rexpiry = now.tv_sec + ns_rr_ttl(rr);
	std::transform(r.rq.qname.begin(), r.rq.qname.end(), r.rq.qname.begin(), ::tolower);
	// check scope, avoid forgery attack
	if (r.rq.qname.size() < scope.size() || r.rq.qname.compare(r.rq.qname.size() - scope.size(), scope.size(), scope) != 0) {
		if (verbose) syslog(LOG_DEBUG, "Ignore record %s which conflicted with scope %s in response from %s", r.rq.qname.c_str(), scope.c_str(), remote_addr);
		return false;
	}
	const unsigned char* pdata = ns_rr_rdata(rr);
	unsigned int sdata = ns_rr_rdlen(rr);
	if (sdata == 0) {
		syslog(LOG_WARNING, "Size of record(rtype %d) in response from %s is too small", r.rq.qtype, remote_addr);
		return false;
	}
	switch (r.rq.qtype) {
	case T_MX:
		if (sdata <= 2) {
			syslog(LOG_WARNING, "Size of MX record in response from %s is too small", remote_addr);
			return false;
		}
		r.rperf = ns_get16(pdata);
		pdata += 2;
		sdata -= 2;
	case T_NS:
	case T_CNAME:
	case T_PTR:
		if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), pdata, domain_name, sizeof(domain_name)) != (int)sdata) {
			syslog(LOG_WARNING, "Failed to uncompress domain name of record(rtype %d) in response from %s", r.rq.qtype, remote_addr);
			return false;
		}
		r.rdata = domain_name;
		std::transform(r.rdata.begin(), r.rdata.end(), r.rdata.begin(), ::tolower);
		break;
	case T_TXT:
	case T_A:
	case T_AAAA:
		r.rdata = std::string((const char*)pdata, sdata);
		break;
	case T_SOA:
		// ignore SOA record
		return false;
	default:
		syslog(LOG_WARNING, "Ignore unsupported record(rtype %d) in response from %s", r.rq.qtype, remote_addr);
		return false;
	}
	bool exist = entries.count(r.rq);
	cache_entry& cache = entries[r.rq];
	if (exist == false) {
		cache.question = r.rq;
		cache.last_update = now.tv_sec + cache_update_min_ttl;
		cache.last_use = now.tv_sec;
	}
	cache.rrs.push_back(r);
	return true;
}

void handle_response(ns_msg& handle, const sockaddr_in& addr) {
	ns_rr rr;
	question_entry question;
	question_entry cnq;
	unsigned short rcode;
	unsigned short id;
	unsigned short rrtype;
	std::map<question_entry, cache_entry> entries;
	ss.rx_response++;
	if (ns_parserr(&handle, ns_s_qd, 0, &rr) < 0) {
		syslog(LOG_WARNING, "Failed to parse the first question in packet received from %s", remote_addr);
		return;
	}
	rcode = ns_msg_getflag(handle, ns_f_rcode);
	id = ns_msg_id(handle);
	question.qname = ns_rr_name(rr);
	question.qtype = ns_rr_type(rr);
	question.qclass = ns_rr_class(rr);
	std::transform(question.qname.begin(), question.qname.end(), question.qname.begin(), ::tolower);
	cnq = question;
	cnq.qtype = T_CNAME;
	// check result
	if (rcode != NXDOMAIN && rcode != NOERROR) {
		syslog(LOG_WARNING, "Drop packet with unsupported rcode %d received from %s", rcode, remote_addr);
		return;
	}
	// then check sender
	if (request_map.count(question) == 0) return;
	request_entry& request = request_map[question];
	if (request.ns.addrs.count(addr) == 0) return;
	if (id != request.ns.addrs[addr]) return;
	
	if (verbose) syslog(LOG_DEBUG, "Received response %d for question %s, %d, %d from %s", request.progress, question.qname.c_str(), question.qclass, question.qtype, remote_addr);
	// first add the answer to cache
	bool no_answer = true;
	for (int i=0;i < ns_msg_count(handle, ns_s_an); i++) {
		if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
			syslog(LOG_WARNING, "Failed to parse the number %d answer in packet received from %s", i, remote_addr);
			return;
		}
		add_response_cache_entry(handle, rr, request.ns.scope, entries, rrtype);
	}
	if (entries.count(question) != 0 || entries.count(cnq) != 0) no_answer = false;
	bool no_ns, no_soa;
	no_ns = no_soa = true;
	// then add authoritative nameservers
	for (int i=0;i < ns_msg_count(handle, ns_s_ns); i++) {
		if (ns_parserr(&handle, ns_s_ns, i, &rr) < 0) {
			syslog(LOG_WARNING, "Failed to parse number %d authoritative record in packet received from %s", i, remote_addr);
			return;
		}
		add_response_cache_entry(handle, rr, request.ns.scope, entries, rrtype);
		if (rrtype == T_NS) no_ns = false;
		else if (rrtype == T_SOA) no_soa = false;
	}
	// last, additional records
	for (int i=0;i < ns_msg_count(handle, ns_s_ar); i++) {
		if (ns_parserr(&handle, ns_s_ar, i, &rr) < 0) {
			syslog(LOG_WARNING, "Failed to parse number %d additional record in packet received from %s", i, remote_addr);
			return;
		}
		add_response_cache_entry(handle, rr, request.ns.scope, entries, rrtype);
	}
	bool no_more_data = no_soa == false || (no_ns == true && no_answer == true);
	bool no_domain = rcode == NXDOMAIN;
	
	for (std::map<question_entry, cache_entry>::iterator it = entries.begin(); it != entries.end(); ++it) {
		// find the least expiry time;
		cache_entry& tmp_cache = it->second;
		tmp_cache.least_expiry = 0;
		for (std::list<resource_entry>::iterator itr = tmp_cache.rrs.begin(); itr != tmp_cache.rrs.end(); ++itr) {
			resource_entry& r = *itr;
			if (tmp_cache.least_expiry == 0 || tmp_cache.least_expiry > r.rexpiry) tmp_cache.least_expiry = r.rexpiry;
		}
		assert(tmp_cache.least_expiry != 0);
		// first delete the old cache_map
		if (cache_map.count(tmp_cache.question) != 0) {
			cache_entry& old_cache = cache_map[tmp_cache.question];
			if (old_cache.least_expiry > tmp_cache.least_expiry) continue;
			tmp_cache.last_use = old_cache.last_use;
			std::set<cache_entry*>& old_cache_expiry = cache_expiry_map[old_cache.least_expiry];
			assert(old_cache_expiry.count(&old_cache) != 0);
			old_cache_expiry.erase(&old_cache);
			if (old_cache_expiry.size() == 0) cache_expiry_map.erase(old_cache.least_expiry);
			ss.cache_replaced++;
		}
		else ss.cache_added++;
		// then add entry to cache_map
		cache_map[tmp_cache.question] = tmp_cache;
		// last, add entry to cache_expiry_map
		cache_expiry_map[tmp_cache.least_expiry].insert(&cache_map[tmp_cache.question]);
		if (cache_map.size() > ss.cache_max) ss.cache_max = cache_map.size();
	}
	
	// try complete request
	assert(request.nq.qclass == request.question.qclass);
	assert(request.nq.qtype == request.question.qtype);
	assert(request.nq.qname == request.question.qname);
	try_complete_request(request, no_more_data, no_domain, request.progress);
	ss.rx_response_accepted++;
}

bool add_request(const question_entry& question, const question_entry* oq, unsigned int progress, const sockaddr_in *addr, unsigned short id,  bool need_answer, bool use_cache, request_entry*& pentry) {
	pentry = NULL;
	bool missing = false;
	// add request to request_map
	if (request_map.count(question) == 0) {
		missing = true;
		request_entry request;
		request.question = question;
		request.nq = question;
		request.progress = oq ? progress : 0;
		request.rexpiry = now.tv_sec + request_timeout;
		request.lastsend.tv_sec = 0;
		request.lastsend.tv_nsec = 0;
		request.retry = 0;
		request.use_cache = use_cache;
		request_map[question] = request;
		pentry = &request_map[question];
		// and request_expiry_map
		request_expiry_map[request.rexpiry].insert(pentry);
		ss.total_request++;
	}
	assert(request_map.count(question) != 0);
	if (pentry == NULL) pentry = &request_map[question];
	if (oq) {
		local_source& ls = pentry->llist[*oq];
		ls.oq = *oq;
		ls.progress = progress;
		ls.need_answer = need_answer;
		ls.base_progress = pentry->progress;
	}
	else if (addr) {
		remote_source rs;
		rs.addr = *addr;
		rs.id = id;
		pentry->rlist.push_back(rs);
	}
	return missing;
}

void handle_request(ns_msg& handle, const sockaddr_in& addr) {
	ns_rr rr;
	question_entry question;
	ss.rx_query++;
	if (ns_parserr(&handle, ns_s_qd, 0, &rr) < 0) {
		syslog(LOG_WARNING, "Failed to parse the first question in packet received from %s", remote_addr);
		return;
	}
	question.qname = ns_rr_name(rr);
	question.qtype = ns_rr_type(rr);
	question.qclass = ns_rr_class(rr);
	std::transform(question.qname.begin(), question.qname.end(), question.qname.begin(), ::tolower);
	if (verbose) syslog(LOG_DEBUG, "Received request %d for question %s, %d, %d from %s", ns_msg_id(handle), question.qname.c_str(), question.qclass, question.qtype, remote_addr);
	request_entry* pentry;
	if (add_request(question, NULL, 0, &addr, ns_msg_id(handle), true, true, pentry)) try_complete_request(*pentry, false, false, pentry->progress);
}

void handle_packet(const unsigned char* buf, int size, sockaddr_in& addr, bool local) {
	ns_msg handle;
	if (ns_initparse(buf,size,&handle) < 0) {
		syslog(LOG_WARNING, "Failed to parse packet received from %s", remote_addr);
		return;
	}
	if (ns_msg_count(handle, ns_s_qd) < 1) {
		syslog(LOG_WARNING, "No question in packet received from %s", remote_addr);
		return;
	}
	if (ns_msg_getflag(handle, ns_f_opcode) != 0) {
		syslog(LOG_WARNING, "Drop packet with unsupported opcode %d received from %s", ns_msg_getflag(handle, ns_f_opcode), remote_addr);
		return;
	}
	if (!!ns_msg_getflag(handle, ns_f_qr) == local) {
		syslog(LOG_WARNING, "Drop unauthorized packet received from %s", remote_addr);
		return;
	}
	if (local) handle_request(handle, addr);
	else handle_response(handle, addr);
}

bool get_answer(question_entry& question, std::vector<resource_entry>& rr, bool use_cache) {
	bool walking = true;
	while (walking) {
		std::map<question_entry, cache_entry>::iterator it = cache_map.find(question);
		if (it != cache_map.end() && (use_cache || it->second.least_expiry > now.tv_sec + cache_update_ttl)) { // found answer
			if (it->second.last_use) it->second.last_use = now.tv_sec;
			rr.insert(rr.end(), it->second.rrs.begin(), it->second.rrs.end());
			return true;
		}
		if (rr.size() >= RESPONSE_MAX_ANSWER_RR) return true; // or there are too many answer
		unsigned short qtype = question.qtype;
		question.qtype = T_CNAME;
		it = cache_map.find(question);
		if (it != cache_map.end() && (use_cache || it->second.least_expiry > now.tv_sec + cache_update_ttl)) { // cname found
			assert(it->second.rrs.size() == 1);
			if (it->second.last_use) it->second.last_use = now.tv_sec;
			rr.insert(rr.end(), it->second.rrs.begin(), it->second.rrs.end());
			question.qname = rr.back().rdata; // try to find the new name
		}
		else walking = false; // break loop
		question.qtype = qtype; // restore type back
	}
	return false;
}

unsigned short add_additional_answer(std::vector<resource_entry>& rr) {
	unsigned short os = rr.size();
	for (int i = 0; i< os; i++) {
		if (rr[i].rq.qtype == T_MX || rr[i].rq.qtype == T_NS) {
			question_entry qa, qaaaa;
			qa.qname = qaaaa.qname = rr[i].rdata;
			qa.qclass = qaaaa.qclass = rr[i].rq.qclass;
			qa.qtype = T_A;
			qaaaa.qtype = T_AAAA;
			get_answer(qa, rr, true);
			get_answer(qaaaa, rr, true);
		}
	}
	return rr.size() - os;
}

void find_nameserver(const question_entry& question, ns_list& ns, std::set<std::string>& ns_with_no_addr) {
	sockaddr_in addr;
	const char* pstr = question.qname.c_str();
	question_entry testns;
	question_entry testa;
	testns.qclass = testa.qclass = C_IN;
	testns.qtype = T_NS;
	testa.qtype = T_A;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53);
	while (ns.addrs.size() == 0 && ns_with_no_addr.size() == 0) {
		assert(pstr);
		testns.qname = ns.scope = pstr;
		if (testns.qname == "") {
			ns.addrs = root_addrs.addrs;
			assert(ns.addrs.size() != 0);
			assert(ns_with_no_addr.size() == 0);
			continue;
		}
		if (cache_map.count(testns)) {
			cache_entry& nscache = cache_map[testns];
			nscache.last_use = 0;
			for (std::list<resource_entry>::iterator itn = nscache.rrs.begin(); itn != nscache.rrs.end(); ++itn) {
				testa.qname = itn->rdata;
				if (cache_map.count(testa)) {
					cache_entry& acache = cache_map[testa];
					acache.last_use = 0;
					for (std::list<resource_entry>::iterator ita = acache.rrs.begin(); ita != acache.rrs.end(); ++ita) {
						assert(ita->rdata.size() == 4);
						addr.sin_addr.s_addr = *((uint32_t*)ita->rdata.c_str());
						ns.addrs.insert(std::make_pair(addr,0));
					}
				}
				else ns_with_no_addr.insert(testa.qname);
			}
			if (ns.addrs.size() == 0 && (question.qtype == T_A || question.qtype == T_AAAA) && ns_with_no_addr.count(question.qname) != 0) ns_with_no_addr.clear();
		}
		pstr = strchr(pstr, '.');
		if (pstr == NULL) pstr = "";
		else ++pstr;
	}
}

void update_request_lastsend(request_entry& request, bool retry, bool delete_only) {
	if (request.lastsend.tv_sec != 0) {
		assert(query_expiry_map.count(request.lastsend) != 0);
		assert(query_expiry_map[request.lastsend].count(&request) != 0);
		query_expiry_map[request.lastsend].erase(&request);
		if (query_expiry_map[request.lastsend].size() == 0) query_expiry_map.erase(request.lastsend);
		request.lastsend.tv_sec = 0;
		request.lastsend.tv_nsec = 0;
	}
	if (delete_only) return;
	if (retry) request.retry++;
	if (request.retry < query_retry) request.lastsend = timespec_add(now, query_timeout);
	if (request.lastsend.tv_sec != 0) query_expiry_map[request.lastsend].insert(&request);
}

bool try_complete_request(request_entry& request, bool no_more_data, bool no_domain, unsigned int progress) {
	assert(request_map.count(request.question) != 0);
	if (request.progress > progress) return false;
	request.progress = progress;
	// first, try to get all answers
	if (get_answer(request.nq, request.anrr, request.use_cache) == true || no_more_data || no_domain || request.progress > QUESTION_MAX_REQUEST) { // we can response now
		// copy result to stack
		request_entry tmp_req = request;
		// remove first, since llist may contain itself
		// eg. cache: ns.domain.com  NS  ns.domain.com, and question: ns.domain.com  A
		assert(request_expiry_map.count(tmp_req.rexpiry) != 0);
		assert(request_expiry_map[tmp_req.rexpiry].count(&request) != 0);
		request_expiry_map[tmp_req.rexpiry].erase(&request);
		if (request_expiry_map[tmp_req.rexpiry].size() == 0) request_expiry_map.erase(tmp_req.rexpiry);
		update_request_lastsend(request, false, true);
		request_map.erase(tmp_req.question);
		// find additional records
		unsigned short adrrc = add_additional_answer(tmp_req.anrr);
		// then response
		if (verbose) syslog(LOG_DEBUG, "Got answer for request(%d) %s, %d, %d: %s %s", tmp_req.progress, tmp_req.question.qname.c_str(), tmp_req.question.qclass, tmp_req.question.qtype, no_more_data ? "NODATA" : "", no_domain ? "NXDOMAIN" : "");
		build_packet(false, no_domain, tmp_req.question, &tmp_req.anrr, adrrc);
		for (std::list<remote_source>::iterator it = tmp_req.rlist.begin(); it != tmp_req.rlist.end(); ++it) {
			ss.tx_response++;
			if (verbose) syslog(LOG_DEBUG, "Send answer to remote %d", it->id);
			send_packet(it->addr,it->id, true);
		}
		for (std::map<question_entry, local_source>::iterator it = tmp_req.llist.begin(); it != tmp_req.llist.end(); ++it) {
			local_source& ls = it->second;
			assert(ls.oq != tmp_req.question);
			if (request_map.count(ls.oq) == 0) continue;
			request_entry& local_request = request_map[ls.oq];
			if ((no_more_data || no_domain) && ls.need_answer == false) continue;
			if (local_request.progress != ls.progress) continue;
			if (verbose) syslog(LOG_DEBUG, "Send answer to local request(%d) %s, %d, %d with new progress %d", local_request.progress, local_request.question.qname.c_str(), local_request.question.qclass, local_request.question.qtype, local_request.progress + tmp_req.progress - ls.base_progress);
			// only recursion when we got the real answer
			try_complete_request(local_request, no_more_data, no_domain, local_request.progress + tmp_req.progress - ls.base_progress);
		}
		if (verbose) syslog(LOG_DEBUG, "Complete request done");
		assert(request_map.count(tmp_req.question) == 0);
		return true;
	}
	// we need solve the new question
	assert(request.nq.qclass == request.question.qclass);
	assert(request.nq.qtype == request.question.qtype);
	if (request.nq != request.question) {
		request.ns.addrs.clear();
		update_request_lastsend(request, false, true);
		if (verbose) syslog(LOG_DEBUG, "Add new request %s, %d, %d for request(%d) %s, %d, %d", request.nq.qname.c_str(), request.nq.qclass, request.nq.qtype, request.progress, request.question.qname.c_str(), request.question.qclass, request.question.qtype);
		request_entry* pentry;
		// may already have answer in cache
		if (add_request(request.nq, &request.question, request.progress, NULL, 0, true, true, pentry)) return try_complete_request(*pentry, false, false, pentry->progress);
		return false;
	}
	std::set<std::string> ns_with_no_addr;
	ns_list new_list;
	find_nameserver(request.question, new_list, ns_with_no_addr);
	if (new_list.addrs.size() != 0) {
		if (new_list.scope != request.ns.scope || new_list.scope.empty() || request.ns.addrs.size() == 0) {
			++request.progress;
			request.ns.addrs.clear();
		}
		build_packet(true, false, request.question, NULL, 0);
		bool update_lastsend = false;
		for (std::map<sockaddr_in, unsigned short>::iterator it = new_list.addrs.begin(); it != new_list.addrs.end(); ++it) {
			if (request.ns.addrs.count(it->first) != 0) continue;
			update_lastsend = true;
			request.ns.addrs[it->first] = rand();
			ss.tx_query++;
			if (verbose) syslog(LOG_DEBUG, "Send query packet for request(%d) %s, %d, %d", request.progress, request.question.qname.c_str(), request.question.qclass, request.question.qtype);
			send_packet(it->first, request.ns.addrs[it->first], false);
		}
		if (update_lastsend) update_request_lastsend(request, false, false);
	}
	else {
		request.ns.addrs.clear();
		update_request_lastsend(request, false, true);
	}
	request.ns.scope = new_list.scope;
	if (ns_with_no_addr.size() != 0) {
		assert(ns_with_no_addr.size() != 0);
		question_entry nsq;
		nsq.qclass = C_IN;
		nsq.qtype = T_A;
		std::map<question_entry, unsigned int> reqs;
		for (std::set<std::string>::iterator it = ns_with_no_addr.begin(); it != ns_with_no_addr.end(); ++it) {
			nsq.qname = *it;
			if (nsq == request.question) continue;
			assert(cache_map.count(nsq) == 0);
			if (verbose) syslog(LOG_DEBUG, "Add new request %s, %d, %d to find A record of nameserver for request(%d) %s, %d, %d", nsq.qname.c_str(), nsq.qclass, nsq.qtype, request.progress, request.question.qname.c_str(), request.question.qclass, request.question.qtype);
			request_entry* pentry;
			if (add_request(nsq, &request.question, request.progress, NULL, 0, false, true, pentry)) reqs[nsq] = pentry->progress;
		}
		for (std::map<question_entry, unsigned int>::iterator it = reqs.begin(); it != reqs.end(); ++it) {
			if (request_map.count(it->first) == 0) continue;
			if (request_map[it->first].progress != it->second) continue;
			try_complete_request(request_map[it->first], false, false, request_map[it->first].progress);
		}
	}
	return false;
}

void send_packet(const sockaddr_in& addr, unsigned short id, bool local) {
	int fd = local ? lfd : rfd;
	fd_set writefds, errorfds;
	HEADER *ph = (HEADER *)sendbuf;
	ph->id = htons(id);
	while (true) {
		FD_ZERO(&writefds);
		FD_ZERO(&errorfds);
		FD_SET(fd, &writefds);
		FD_SET(fd, &errorfds);
		if (select(fd+1, NULL, &writefds, &errorfds, NULL) < 0) {
			if (errno == EINTR) continue;
			syslog(LOG_WARNING, "select(send_packet) encountered an error %d", errno);
			return;
		}
		if (FD_ISSET(fd, &errorfds)) {
			syslog(LOG_WARNING, "socket(send_packet) error");
			return;
		}
		assert(FD_ISSET(fd, &writefds));
		if (sendto(fd, sendbuf, pspos - sendbuf, 0, (const sockaddr*)&addr, sizeof(addr)) < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
			syslog(LOG_WARNING, "sendto encountered an error %d", errno);
		}
		break;
	}
}

void build_packet(bool query, bool no_domain, const question_entry& question, const std::vector<resource_entry>* anrr, unsigned short adrrc) {
	HEADER *ph = (HEADER *)sendbuf;
	const unsigned char *dnptrs[RESPONSE_MAX_ANSWER_RR+2], **lastdnptr;
	unsigned short *prsize;
	unsigned short rsize;
	int n;
	pspos = (unsigned char *)(ph + 1);
	lastdnptr = dnptrs + sizeof(dnptrs) / sizeof(dnptrs[0]);
	memset(sendbuf,0,sizeof(sendbuf));
	dnptrs[0]=sendbuf;
	dnptrs[1]=NULL;
	ph->qr = !query;
	ph->rd = query ? (custom_root.size() ? true : false) : false;
	ph->ra = query ? false : true;
	ph->rcode = no_domain? NXDOMAIN : NOERROR;
	if (psend - pspos < QFIXEDSZ) {
		syslog(LOG_WARNING, "Not enough fixed buff to build question: %s, %d, %d", question.qname.c_str(), question.qclass, question.qtype);
		return;
	}
	if ((n = ns_name_compress(question.qname.c_str(), pspos, psend - pspos - QFIXEDSZ, dnptrs, lastdnptr)) < 0) {
		syslog(LOG_WARNING, "Not enough buff to build question: %s, %d, %d", question.qname.c_str(), question.qclass, question.qtype);
		return;
	}
	pspos += n;
	ns_put16(question.qtype, pspos);	pspos += INT16SZ;
	ns_put16(question.qclass, pspos);	pspos += INT16SZ;
	ph->qdcount = htons(1);
	for (int i = 0; anrr && i < (int)anrr->size() && i < RESPONSE_MAX_ANSWER_RR;) {
		const resource_entry& r = (*anrr)[i];
		if (psend - pspos < RRFIXEDSZ) {
			syslog(LOG_WARNING, "Not enough fixed buff to build answer %d for question: %s, %d, %d", i, question.qname.c_str(), question.qclass, question.qtype);
			return;
		}
		if ((n = ns_name_compress(r.rq.qname.c_str(), pspos, psend - pspos - RRFIXEDSZ, dnptrs, lastdnptr)) < 0) {
			syslog(LOG_WARNING, "Not enough buff to build answer %d for question: %s, %d, %d", i, question.qname.c_str(), question.qclass, question.qtype);
			return;
		}
		pspos += n;
		ns_put16(r.rq.qtype, pspos);	pspos += INT16SZ;
		ns_put16(r.rq.qclass, pspos);	pspos += INT16SZ;
		ns_put32(r.rexpiry > now.tv_sec ? r.rexpiry - now.tv_sec : 0, pspos);	pspos += INT32SZ;
		prsize = (unsigned short *)pspos;
		ns_put16(rsize = 0, pspos);		pspos += INT16SZ;
		switch (r.rq.qtype) {
		case T_MX:
			if (psend - pspos < INT16SZ) {
				syslog(LOG_WARNING, "Not enough fixed buff to build MX answer %d for question: %s, %d, %d", i, question.qname.c_str(), question.qclass, question.qtype);
				return;
			}
			ns_put16(r.rperf, pspos);	pspos += INT16SZ;		rsize += INT16SZ;
		case T_NS:
		case T_CNAME:
		case T_PTR:
			if ((n = ns_name_compress(r.rdata.c_str(), pspos, psend - pspos, dnptrs, lastdnptr)) < 0) {
				syslog(LOG_WARNING, "Failed to compress domain name %s in answer %d(rtype %d) for question: %s, %d, %d", r.rdata.c_str(), i, r.rq.qtype, question.qname.c_str(), question.qclass, question.qtype);
				return;
			}
			pspos += n;
			rsize += n;
			break;
		case T_TXT:
		case T_A:
		case T_AAAA:
			if (psend - pspos < (int)r.rdata.size()) {
				syslog(LOG_WARNING, "Not enough buff to build answer %d(rtype %d, rsize %d) for question: %s, %d, %d", i, r.rq.qtype, (int)r.rdata.size(), question.qname.c_str(), question.qclass, question.qtype);
				return;
			}
			memcpy(pspos, r.rdata.c_str(), r.rdata.size());
			pspos += r.rdata.size();
			rsize += r.rdata.size();
			break;
		default:
			syslog(LOG_WARNING, "Failed to build answer %d(unsupported rtype %d) for question: %s, %d, %d", i, r.rq.qtype, question.qname.c_str(), question.qclass, question.qtype);
			return;
		}
		*prsize = htons(rsize);
		++i;
		ph->ancount = htons((i > (int)anrr->size() - adrrc) ? anrr->size() - adrrc : i);
		ph->arcount = htons((i > (int)anrr->size() - adrrc) ? i + adrrc - anrr->size() : 0);
	}
}

void check_expiry() {
	// first, check request
	for (; request_expiry_map.begin() != request_expiry_map.end() && request_expiry_map.begin()->first <= now.tv_sec; ) {
		std::set<request_entry*>::iterator itr;
		for (itr = request_expiry_map.begin()->second.begin(); itr != request_expiry_map.begin()->second.end(); ++itr) {
			request_entry *r = *itr;
			question_entry q = r->question;
			assert(request_map.count(q) != 0);
			assert(request_map[q].rexpiry == request_expiry_map.begin()->first);
			ss.request_timeout++;
			update_request_lastsend(request_map[q], false, true);
			if (verbose) syslog(LOG_DEBUG, "Remove timed out request(%d) %s, %d, %d", r->progress, q.qname.c_str(), q.qclass, q.qtype);
			request_map.erase(q);
		}
		request_expiry_map.erase(request_expiry_map.begin());
	}
	// then, check query
	for (; query_expiry_map.begin() != query_expiry_map.end() && query_expiry_map.begin()->first < now; ) {
		request_entry *r = *query_expiry_map.begin()->second.begin();
		question_entry q = r->question;
		assert(request_map.count(q) != 0);
		assert(request_map[q].lastsend.tv_sec == query_expiry_map.begin()->first.tv_sec);
		assert(request_map[q].lastsend.tv_nsec == query_expiry_map.begin()->first.tv_nsec);
		assert(r->question == r->nq);
		assert(r->ns.addrs.size() != 0);
		assert(r->retry < query_retry);
		ss.query_retry++;
		build_packet(true, false, r->question, NULL, 0);
		for (std::map<sockaddr_in, unsigned short>::iterator its = r->ns.addrs.begin(); its != r->ns.addrs.end(); ++its) {
			ss.tx_query++;
			if (verbose) syslog(LOG_DEBUG, "Resend query for request(%d) %s, %d, %d", r->progress, r->question.qname.c_str(), r->question.qclass, r->question.qtype);
			send_packet(its->first, r->ns.addrs[its->first], false);
		}
		update_request_lastsend(*r, true, false);
	}
	// last, remove and refresh cache
	for (std::map<time_t, std::set<cache_entry*> >::iterator it = cache_expiry_map.begin(); it != cache_expiry_map.end() && it->first <= now.tv_sec + cache_update_ttl; ) {
		std::set<cache_entry*>::iterator itc;
		for (itc = it->second.begin(); itc != it->second.end(); ++itc) {
			cache_entry* centry = *itc;
			assert(cache_map.count(centry->question) != 0);
			assert(&cache_map[centry->question] == centry);
			assert(cache_map[centry->question].least_expiry == it->first);
			if (centry->least_expiry <= now.tv_sec) {
				question_entry q = centry->question;
				ss.cache_timeout++;
				if (verbose) syslog(LOG_DEBUG, "Remove expired cache %s, %d, %d", q.qname.c_str(), q.qclass, q.qtype);
				cache_map.erase(q);
				continue;
			}
			if (centry->last_update > now.tv_sec - cache_update_interval) continue;
			if (centry->last_use != 0) {
				if (cache_map.size() > cache_hard_watermark) continue;
				else if (cache_map.size() > cache_soft_watermark && centry->last_use < now.tv_sec - cache_soft_lru) continue;
			}
			ss.cache_refresh++;
			if (verbose) syslog(LOG_DEBUG, "Refresh cache(%d) %s, %d, %d", (int)(centry->least_expiry - now.tv_sec), centry->question.qname.c_str(), centry->question.qclass, centry->question.qtype);
			centry->last_update = now.tv_sec;
			request_entry* rentry;
			if (add_request(centry->question, NULL, 0, NULL, 0, false, false, rentry)) try_complete_request(*rentry, false, false, rentry->progress);
		}
		if (it->first <= now.tv_sec) cache_expiry_map.erase(it++);
		else ++it;
	}
}

bool parse_option(int argc, char **argv) {
	int c;
	while ((c = getopt(argc, argv, "b:p:r:t:i:n:s:l:d:o:q:y:vh")) != -1) {
		switch (c) {
		case 'b':
			if (inet_aton(optarg, &bind_address) == 0) return false;
			break;
		case 'p':
			bind_port = atoi(optarg);
			break;
		case 'r':
			custom_root.push_back(optarg);
			break;
		case 't':
			cache_update_ttl = atoi(optarg);
			break;
		case 'i':
			cache_update_interval = atoi(optarg);
			break;
		case 'n':
			cache_update_min_ttl = atoi(optarg);
			break;
		case 's':
			cache_soft_watermark = atoi(optarg);
			break;
		case 'l':
			cache_soft_lru = atoi(optarg);
			break;
		case 'd':
			cache_hard_watermark = atoi(optarg);
			break;
		case 'o':
			request_timeout = atoi(optarg);
			break;
		case 'q':
			query_timeout = atoi(optarg);
			break;
		case 'y':
			query_retry = atoi(optarg);
			break;
		case 'v':
			verbose = true;
			break;
		default:
			print_help();
			return false;
		}
	}
	return true;
}
