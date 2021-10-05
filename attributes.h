#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#if __has_attribute(noreturn)
#define NORETURN __attribute__((noreturn))
#else
#define NORETURN
#endif

#if __has_attribute(unused)
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

#if __has_attribute(fallthrough)
#define FALLTHROUGH __attribute__((fallthrough))
#else
#define FALLTHROUGH
#endif

#endif
