#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* Minimal stub to avoid conflicts between libbpf helper defs and bcc helpers.
 * We rely on bcc/helpers.h for helper prototypes; only SEC macro needed here.
 */
#define SEC(NAME) __attribute__((section(NAME), used))

#endif /* __BPF_HELPERS_H */
