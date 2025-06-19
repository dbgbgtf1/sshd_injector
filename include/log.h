#ifndef LOG
#define LOG

#include <stdlib.h>
#include <stdio.h>

#define PERROR(s)                                                             \
  {                                                                           \
    perror (s);                                                               \
    exit (-1);                                                                \
  }

#define PEXIT(s)                                                              \
  {                                                                           \
    puts (s);                                                                 \
    exit (-1);                                                                \
  }

#endif
