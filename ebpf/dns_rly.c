#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <stddef.h>
#include <string.h>


#define MAX_SOCKS 64
char dns_buffer[512];
// struct {
// 	__uint(type, BPF_MAP_TYPE_XSKMAP);
// 	__uint(max_entries, MAX_SOCKS);
// 	__uint(key_size, sizeof(int));
// 	__uint(value_size, sizeof(int));
// 	__uint(pinning, LIBBPF_PIN_BY_NAME);
// } xsks_map SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, MAX_SOCKS);
// 	__uint(key_size, sizeof(int));
// 	__uint(value_size, sizeof(int));
// 	__uint(pinning, LIBBPF_PIN_BY_NAME);
// } qidconf_map SEC(".maps");

struct dns_hdr
{
    __u16 transaction_id;
    __u8 rd : 1;      //Recursion desired
    __u8 tc : 1;      //Truncated
    __u8 aa : 1;      //Authoritive answer
    __u8 opcode : 4;  //Opcode
    __u8 qr : 1;      //Query/response flag
    __u8 rcode : 4;   //Response code
    __u8 cd : 1;      //Checking disabled
    __u8 ad : 1;      //Authenticated data
    __u8 z : 1;       //Z reserved bit
    __u8 ra : 1;      //Recursion available
    __u16 q_count;    //Number of questions
    __u16 ans_count;  //Number of answer RRs
    __u16 auth_count; //Number of authority RRs
    __u16 add_count;  //Number of resource RRs
};

#define MAX_DNS_NAME_LENGTH 256

struct dns_query {
    __u16 record_type;
    __u16 class;
    char name[MAX_DNS_NAME_LENGTH];
};


struct a_record {
    struct in_addr ip_addr;
    __u32 ttl;
};


struct dns_response {
   // char name[MAX_DNS_NAME_LENGTH];
   __u16 record_type;
   __u16 class;
   __u32 ttl;
   __u16 data_length;
} __attribute__((packed));


struct ar_hdr {
    __u8 name;
    __u16 type;
    __u16 size;
    __u32 ex_rcode;
    __u16 rcode_len;
} __attribute__((packed));

//Parse query and return query length
static int parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q)
{
    void *data_end = (void *)(long)ctx->data_end;

    // #ifdef DEBUG
    // bpf_printk("Parsing query");
    // #endif

    int i;
    void *cursor = query_start;
    int namepos = 0;

    //Fill dns_query.name with zero bytes
    //Not doing so will make the verifier complain when dns_query is used as a key in bpf_map_lookup
    memset(&q->name[0], 0, sizeof(q->name));
    //Fill record_type and class with default values to satisfy verifier
    q->record_type = 0;
    q->class = 0;

    //We create a bounded loop of MAX_DNS_NAME_LENGTH (maximum allowed dns name size).
    //We'll loop through the packet byte by byte until we reach '0' in order to get the dns query name
    for (i = 0; i < MAX_DNS_NAME_LENGTH; i++)
    {
        //Boundary check of cursor. Verifier requires a +1 here. 
        //Probably because we are advancing the pointer at the end of the loop
        if (cursor + 1 > data_end)
        {
            // #ifdef DEBUG
            // bpf_printk("Error: boundary exceeded while parsing DNS query name");
            // #endif
            break;
        }

        /*
        #ifdef DEBUG
        bpf_printk("Cursor contents is %u\n", *(char *)cursor);
        #endif
        */

        //If separator is zero we've reached the end of the domain query
        if (*(char *)(cursor) == 0)
        {

            //We've reached the end of the query name.
            //This will be followed by 2x 2 bytes: the dns type and dns class.
            if (cursor + 5 > data_end)
            {
                // #ifdef DEBUG
                // bpf_printk("Error: boundary exceeded while retrieving DNS record type and class");
                // #endif
            }
            else
            {
                q->record_type = bpf_htons(*(__u16 *)(cursor + 1));
                q->class = bpf_htons(*(__u16 *)(cursor + 3));
            }

            //Return the bytecount of (namepos + current '0' byte + dns type + dns class) as the query length.
            return namepos + 1 + 2 + 2;
        }

        //Read and fill data into struct
        q->name[namepos] = *(char *)(cursor);
        namepos++;
        cursor++;
    }

    return -1;
}

static int match_a_records(struct xdp_md *ctx, struct dns_query *q, struct a_record *a)
{
    // #ifdef DEBUG
    // bpf_printk("DNS record type: %i", q->record_type);
    // bpf_printk("DNS class: %i", q->class);
    //bpf_printk("DNS name: %s %u", q->name, sizeof(q->name));
    // #endif
  
    struct a_record *record;
    // #ifdef BCC_SEC
    // record = xdns_a_records.lookup(q);
    // #else
    // record = bpf_map_lookup_elem(&xdns_a_records, q);
    // #endif

    a->ip_addr.s_addr = 0x03030303;
    a->ttl = 30;
    return 0;
    // 3.3.3.3
    // record->ip_addr.s_addr = 0x03030303;
    // bpf_printk("query_length %u", 0x30);
    // record->ttl = 3600; // 1 hour TTL
    // bpf_printk("query_length %u", 0x30);
    // //If record pointer is not zero..
    // if (record > 0)
    // {
    //     bpf_printk("DNS query matched");
    //     #ifdef DEBUG
    //     bpf_printk("DNS query matched");
    //     #endif
    //     a->ip_addr = record->ip_addr;
    //     a->ttl = record->ttl;

    //     return 0;
    // }

    // return -1;
}

static void modify_dns_header_response(struct dns_hdr *dns_hdr)
{
    //Set query response
    dns_hdr->qr = 1;
    //Set truncated to 0
    //dns_hdr->tc = 0;
    //Set authorative to zero
    //dns_hdr->aa = 0;
    //Recursion available
    dns_hdr->ra = 1;
    //One answer
    dns_hdr->ans_count = bpf_htons(1);
}

static void create_query_response(struct a_record *a,struct dns_query *q, char *dns_buffer, size_t *buf_size)
{
    //Formulate a DNS response. Currently defaults to hardcoded query pointer + type a + class in + ttl + 4 bytes as reply.

    memcpy(&dns_buffer[0], q->name, sizeof(q->name));

    struct dns_response *response = (struct dns_response *) &dns_buffer[14];
    // strcpy(response->name, q->name);
    // memcpy(&response->name[0], q->name, sizeof(q->name));
    response->record_type = bpf_htons(0x0001);
    response->class = bpf_htons(0x0001);
    response->ttl = bpf_htonl(a->ttl); // 30 seconds TTL
    response->data_length = bpf_htons((__u16)sizeof(a->ip_addr));
    *buf_size += sizeof(struct dns_response);
    *buf_size += 14;
    //Copy IP address
    __builtin_memcpy(&dns_buffer[*buf_size], &a->ip_addr, sizeof(struct in_addr));
    *buf_size += sizeof(struct in_addr);
}

//Update IP checksum for IP header, as specified in RFC 1071
//The checksum_location is passed as a pointer. At this location 16 bits need to be set to 0.
static void update_ip_checksum(void *data, int len, __u16 *checksum_location)
{
    __u32 accumulator = 0;
    int i;
    for (i = 0; i < len; i += 2)
    {
        __u16 val;
        //If we are currently at the checksum_location, set to zero
        if (data + i == checksum_location)
        {
            val = 0;
        }
        else
        {
            //Else we load two bytes of data into val
            val = *(__u16 *)(data + i);
        }
        accumulator += val;
    }

    //Add 16 bits overflow back to accumulator (if necessary)
    __u16 overflow = accumulator >> 16;
    accumulator &= 0x00FFFF;
    accumulator += overflow;

    //If this resulted in an overflow again, do the same (if necessary)
    accumulator += (accumulator >> 16);
    accumulator &= 0x00FFFF;

    //Invert bits and set the checksum at checksum_location
    __u16 chk = accumulator ^ 0xFFFF;

    #ifdef DEBUG
    bpf_printk("Checksum: %u", chk);
    #endif

    *checksum_location = chk;
}

static void copy_to_pkt_buf(struct xdp_md *ctx, void *dst, void *src, size_t n)
{
    //Boundary check
    if((void *)(long)ctx->data_end >= dst + n){
        int i;
        char *cdst = dst;
        char *csrc = src;

        //For A records, src is either 16 or 27 bytes, depending if OPT record is requested.
        //Use __builtin_memcpy for this. Otherwise, use our own slow, naive memcpy implementation.
        switch(n)
        {
            case 16:
                __builtin_memcpy(cdst, csrc, 16);
                break;
            
            case 27:
                __builtin_memcpy(cdst, csrc, 27);
                break;

            default:
                for(i = 0; i < n; i+=1)
                {
                    cdst[i] = csrc[i];
                }
        }
    }
}

static void swap_mac(__u8 *src_mac, __u8 *dst_mac)
{
    int i;
    for (i = 0; i < 6; i++)
    {
        __u8 tmp_src;
        tmp_src = *(src_mac + i);
        *(src_mac + i) = *(dst_mac + i);
        *(dst_mac + i) = tmp_src;
    }
}

static inline int parse_ar(struct xdp_md *ctx, struct dns_hdr *dns_hdr, int query_length, struct ar_hdr *ar)
{
    #ifdef DEBUG
    bpf_printk("Parsing additional record in query");
    #endif

    void *data_end = (void *)(long)ctx->data_end;

    //Parse ar record
    ar  = (void *) dns_hdr + query_length + sizeof(struct dns_response);
    if((void*) ar + sizeof(struct ar_hdr) > data_end){
        #ifdef DEBUG
        bpf_printk("Error: boundary exceeded while parsing additional record");
        #endif
        return -1;
    }

    return 0;
}

static inline int create_ar_response(struct ar_hdr *ar, char *dns_buffer, size_t *buf_size)
{
    //Check for OPT record (RFC6891)
    if(ar->type == bpf_htons(41)){
        #ifdef DEBUG
        bpf_printk("OPT record found");
        #endif
        struct ar_hdr *ar_response = (struct ar_hdr *) &dns_buffer[0];
        //We've received an OPT record, advertising the clients' UDP payload size
        //Respond that we're serving a payload size of 512 and not serving any additional records.
        ar_response->name = 0;
        ar_response->type = bpf_htons(41);
        ar_response->size = bpf_htons(512);
        ar_response->ex_rcode = 0;
        ar_response->rcode_len = 0;

        *buf_size += sizeof(struct ar_hdr);
    }
    else
    {
        return -1;
    }
        
    return 0;
}

SEC("xdp") int xdp_sock_prog(struct xdp_md *ctx)
{

	// int *qidconf, index = ctx->rx_queue_index;
	// // A set entry here means that the correspnding queue_id
	// // has an active AF_XDP socket bound to it.
	// qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	// if (!qidconf)
	// 	return XDP_PASS;

	// redirect packets to an xdp socket that match the given IPv4 or IPv6 protocol; pass all other packets to the kernel
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 h_proto = eth->h_proto;
	if ((void*)eth + sizeof(*eth) <= data_end) {
		if (bpf_htons(h_proto) == ETH_P_IP) {
			struct iphdr *ip = data + sizeof(*eth);
			if ((void*)ip + sizeof(*ip) <= data_end) {
				if (ip->protocol == IPPROTO_UDP) {
                    struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
                    if ((void*)udp + sizeof(*udp) <= data_end) {
                        if (udp->dest == bpf_htons(53)) {
                            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dns_hdr) > data_end)
                            {
                                return XDP_PASS;
                            }

                            struct dns_hdr *dns_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);

                            //Check if header contains a standard query
                            if (dns_hdr->qr == 0 && dns_hdr->opcode == 0)
                            {
                                // #ifdef DEBUG
                                //bpf_printk("DNS query transaction id %u", bpf_ntohs(dns_hdr->transaction_id));
                                // #endif

                                //Get a pointer to the start of the DNS query
                                void *query_start = (void *)dns_hdr + sizeof(struct dns_hdr);

                                //We will only be parsing a single query for now
                                struct dns_query q;
                                int query_length = 0;
                                query_length = parse_query(ctx, query_start, &q);
                                if (query_length < 1)
                                {
                                    return XDP_PASS;
                                }

                                //Check if query matches a record in our hash table
                                struct a_record a_record;
                                int res = match_a_records(ctx, &q, &a_record);
                                //If query matches...
                                if (res == 0)
                                {
                                    
                                    size_t buf_size = 0;

                                    //Change DNS header to a valid response header
                                    modify_dns_header_response(dns_hdr);

                                    //Create DNS response and add to temporary buffer.
                                    create_query_response(&a_record, &q, &dns_buffer[buf_size], &buf_size);
                                    //If an additional record is present
                                    if(dns_hdr->add_count > 0)
                                    {
                                        // Parse AR record
                                        struct ar_hdr ar;
                                        if(parse_ar(ctx, dns_hdr, query_length, &ar) != -1)
                                        {     
                                            //Create AR response and add to temporary buffer
                                            create_ar_response(&ar, &dns_buffer[buf_size], &buf_size);
                                        }
                                    }
                                    //Start our response [query_length] bytes beyond the header
                                    void *answer_start = (void *)dns_hdr + sizeof(struct dns_hdr) + query_length;
                                    //Determine increment of packet buffer
                                    int tailadjust = answer_start + buf_size - data_end;

                                    //Adjust packet length accordingly
                                    if (bpf_xdp_adjust_tail(ctx, tailadjust))
                                    {
                                        #ifdef DEBUG
                                        bpf_printk("Adjust tail fail");
                                        #endif
                                    }
                                    else
                                    {
                                        //Because we adjusted packet length, mem addresses might be changed.
                                        //Reinit pointers, as verifier will complain otherwise.
                                        data = (void *)(unsigned long)ctx->data;
                                        data_end = (void *)(unsigned long)ctx->data_end;

                                        //Copy bytes from our temporary buffer to packet buffer
                                        copy_to_pkt_buf(ctx, data + sizeof(struct ethhdr) +
                                                sizeof(struct iphdr) +
                                                sizeof(struct udphdr) +
                                                sizeof(struct dns_hdr) +
                                                query_length,
                                            &dns_buffer[0], buf_size);

                                        eth = data;
                                        ip = data + sizeof(struct ethhdr);
                                        udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

                                        //Do a new boundary check
                                        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
                                        {
                                            #ifdef DEBUG
                                            bpf_printk("Error: Boundary exceeded");
                                            #endif
                                            return XDP_PASS;
                                        }

                                        //Adjust UDP length and IP length
                                        __u16 iplen = (data_end - data) - sizeof(struct ethhdr);
                                        __u16 udplen = (data_end - data) - sizeof(struct ethhdr) - sizeof(struct iphdr);
                                        ip->tot_len = bpf_htons(iplen);
                                        udp->len = bpf_htons(udplen);

                                        //Swap eth macs
                                        swap_mac((__u8 *)eth->h_source, (__u8 *)eth->h_dest);

                                        //Swap src/dst IP
                                        __u32 src_ip = ip->saddr;
                                        ip->saddr = ip->daddr;
                                        ip->daddr = src_ip;

                                        //Set UDP checksum to zero
                                        udp->check = 0;

                                        //Swap udp src/dst ports
                                        __u16 tmp_src = udp->source;
                                        udp->source = udp->dest;
                                        udp->dest = tmp_src;

                                        //Recalculate IP checksum
                                        update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

                                        // #ifdef DEBUG
                                        // bpf_printk("XDP_TX");
                                        // #endif

                            
                                        // #ifdef DEBUG
                                        // uint64_t end = bpf_ktime_get_ns();
                                        // uint64_t elapsed = end-start;
                                        // bpf_printk("Time elapsed: %d", elapsed);
                                        // #endif

                                        //Emit modified packet
                                        return XDP_TX;
                                    }
                                }
                            }
                        }
                    }
				}
			}
		// } else if (bpf_htons(h_proto) == ETH_P_IPV6) {
		// 	struct ipv6hdr *ip = data + sizeof(*eth);
		// 	if ((void*)ip + sizeof(*ip) <= data_end) {
		// 		if (ip->nexthdr == IPPROTO_UDP) {
        //             struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
        //             if ((void*)udp + sizeof(*udp) <= data_end) {
        //                 if (udp->dest == bpf_htons(53)) {

        //                 }
        //             }
		// 		}
		// 	}
		}
	}

	return XDP_PASS;
}




//Basic license just for compiling the object code
char _license[] SEC("license") = "GPL";
