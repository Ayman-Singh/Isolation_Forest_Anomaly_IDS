#ifndef __BPF_ENDIAN_STUB_H__
#define __BPF_ENDIAN_STUB_H__

/* Minimal endian helpers for BCC builds without pulling libbpf headers */
#ifndef __u16
#define __u16 unsigned short
#endif
#ifndef __u32
#define __u32 unsigned int
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) (__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) (__builtin_bswap16((__u16)(x)))
#define bpf_htonl(x) (__builtin_bswap32((__u32)(x)))
#define bpf_ntohl(x) (__builtin_bswap32((__u32)(x)))
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohl(x) (x)
#endif

#endif /* __BPF_ENDIAN_STUB_H__ */
