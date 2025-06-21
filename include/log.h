#ifndef LOG
#define LOG

#include <stdio.h>
#include <stdlib.h>

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
