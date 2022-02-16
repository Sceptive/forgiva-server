#include "types.h"

#ifndef _HAVE_DEBUG_H
#define _HAVE_DEBUG_H


#ifdef FORGIVA_DEBUG
#pragma message ( "BUILDING IN DEBUG MODE" )
#endif

extern int F_MAX_DEBUG_LEVEL;

extern int F_MAX_BUFFER;

extern int F_MAX_COLUMN_TO_PRINT;

extern FILE *F_DEBUG_FILE;

void f_debug_close_file();

void f_set_debug_file(f_byte *file_name);

void f_set_debug_level(int _level);

f_byte *f_debug_date_header();

void forgiva_debug_n(int debug_level, const char *format, ...);
void v_forgiva_debug(int debug_level, f_byte *description, void *data,
                     f_uint data_len, const char *format, va_list args);
void forgiva_debug_s(f_byte *description);
void forgiva_debug_m(int debug_level, f_byte *description);
void forgiva_debug_l(int debug_level, void *data, f_uint data_len);

void forgiva_debug(int debug_level, f_byte *description, void *data,
                   f_uint data_len, const char *format, ...);
void forgiva_debug_bd(int debug_level, f_byte *description, byte_data *data);
void forgiva_debug_d(int debug_level, f_byte *description, void *data,
                     f_uint data_len);

#ifndef WIN32
#define cBLK "\x1b[0;30m"
#define cRED "\x1b[0;31m"
#define cGRN "\x1b[0;32m"
#define cBRN "\x1b[0;33m"
#define cBLU "\x1b[0;34m"
#define cMGN "\x1b[0;35m"
#define cCYA "\x1b[0;36m"
#define cLGR "\x1b[0;37m"
#define cGRA "\x1b[1;90m"
#define cLRD "\x1b[1;91m"
#define cLGN "\x1b[1;92m"
#define cYEL "\x1b[1;93m"
#define cLBL "\x1b[1;94m"
#define cPIN "\x1b[1;95m"
#define cLCY "\x1b[1;96m"
#define cBRI "\x1b[1;97m"
#define cRST "\x1b[0m"

#define bgBLK "\x1b[40m"
#define bgRED "\x1b[41m"
#define bgGRN "\x1b[42m"
#define bgBRN "\x1b[43m"
#define bgBLU "\x1b[44m"
#define bgMGN "\x1b[45m"
#define bgCYA "\x1b[46m"
#define bgLGR "\x1b[47m"
#define bgGRA "\x1b[100m"
#define bgLRD "\x1b[101m"
#define bgLGN "\x1b[102m"
#define bgYEL "\x1b[103m"
#define bgLBL "\x1b[104m"
#define bgPIN "\x1b[105m"
#define bgLCY "\x1b[106m"
#define bgBRI "\x1b[107m"
#else
#define cBLK
#define cRED
#define cGRN
#define cBRN
#define cBLU
#define cMGN
#define cCYA
#define cLGR
#define cGRA
#define cLRD
#define cLGN
#define cYEL
#define cLBL
#define cPIN
#define cLCY
#define cBRI
#define cRST

#define bgBLK
#define bgRED
#define bgGRN
#define bgBRN
#define bgBLU
#define bgMGN
#define bgCYA
#define bgLGR
#define bgGRA
#define bgLRD
#define bgLGN
#define bgYEL
#define bgLBL
#define bgPIN
#define bgLCY
#define bgBRI
#endif

//#ifdef MESSAGES_TO_STDOUT
#ifdef WIN32
#define SAYF(...) fprintf(stdout, __VA_ARGS__)
#else
#define SAYF(x...) printf((char *)x)
#endif
//#else
//#define SAYF(x...) fprintf(stderr, x)
//#endif /* ^MESSAGES_TO_STDOUT */

#define TERM_HOME "\x1b[H"
#define TERM_CLEAR TERM_HOME "\x1b[2J"
#define cEOL "\x1b[0K"
#define CURSOR_HIDE "\x1b[?25l"
#define CURSOR_SHOW "\x1b[?25h"

#ifdef WIN32

#define F_DEBUG(...)                                                           \
  do {                                                                         \
    if (1) {                                                                   \
      forgiva_debug(F_DEBUG_S, __VA_ARGS__);                                   \
    }                                                                          \
  } while (0)

#else
#define F_DEBUG(x, ...)                                                        \
  do {                                                                         \
    if (1) {                                                                   \
      forgiva_debug(F_DEBUG_S, x);                                             \
    }                                                                          \
  } while (0)
#endif

#ifdef WIN32
#define WARNF(...)                                                             \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0,                 \
                  "WARNF:" __VA_ARGS__);                                       \
    SAYF(cYEL "[!] " cBRI "WARNING: " cRST __VA_ARGS__);                       \
    SAYF(cRST "\n");                                                           \
  } while (0)
#else
#define WARNF(x...)                                                          \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0, "WARNF:" x);    \
    SAYF(cYEL "[!] " cBRI "WARNING: " cRST x);                                 \
    SAYF(cRST "\n");                                                           \
  } while (0)
#endif

#ifdef WIN32
#define ACTF(...)                                                              \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0,                 \
                  "ACTF:" __VA_ARGS__);                                        \
    SAYF(cLBL "[*] " cRST __VA_ARGS__);                                        \
    SAYF(cRST "\n");                                                           \
  } while (0)
#else
#define ACTF(x...)                                                             \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0, "ACTF:" x);     \
    SAYF(cLBL "[*] " cRST x);                                                  \
    SAYF(cRST "\n");                                                           \
  } while (0)
#endif

#ifdef WIN32
#define OKF(...)                                                               \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0,                 \
                  "OKF:" __VA_ARGS__);                                         \
    SAYF(cLGN "[+] " cRST __VA_ARGS__);                                        \
    SAYF(cRST "\n");                                                           \
  } while (0)
#else
#define OKF(x...)                                                              \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0, "OKF:" x);      \
    SAYF(cLGN "[+] " cRST x);                                                  \
    SAYF(cRST "\n");                                                           \
  } while (0)
#endif

#ifdef WIN32
#define FATAL(...)                                                             \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0,                 \
                  "FATAL: %s(), %s:%u " __VA_ARGS__, __FUNCTION__, __FILE__,   \
                  __LINE__);                                                   \
    SAYF(CURSOR_SHOW cRST cLRD "\n[-] " cBRI __VA_ARGS__);                     \
    exit(1);                                                                   \
  } while (0)
#else
#define FATAL(x...)                                                            \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0,                 \
                  "FATAL: %s(), %s:%u " x, __FUNCTION__, __FILE__, __LINE__);  \
    SAYF(CURSOR_SHOW cRST cLRD "\n[-] " cBRI x);                               \
    exit(1);                                                                   \
  } while (0)
#endif
#ifdef WIN32
#define ABORT(...)                                                             \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0,                 \
                  "ABORT: %s(), %s:%u " __VA_ARGS__, __FUNCTION__, __FILE__,   \
                  __LINE__);                                                   \
    SAYF(CURSOR_SHOW cRST cLRD "\n[-] FORGIVA ABORTS : " cBRI __VA_ARGS__);    \
    SAYF(cLRD "\n    Stop location : " cRST "%s(), %s:%u\n\n", __FUNCTION__,   \
         __FILE__, __LINE__);                                                  \
    abort();                                                                   \
  } while (0)
#else
#define ABORT(x, ...)                                                          \
  do {                                                                         \
    forgiva_debug(F_DEBUG_INTERMEDIATE, fstr("CORE"), NULL, 0,                 \
                  "ABORT: %s(), %s:%u " x, __FUNCTION__, __FILE__, __LINE__);  \
    SAYF(CURSOR_SHOW cRST cLRD "\n[-] FORGIVA ABORTS : " cBRI x);              \
    SAYF(cLRD "\n    Stop location : " cRST "%s(), %s:%u\n\n", __FUNCTION__,   \
         __FILE__, __LINE__);                                                  \
    abort();                                                                   \
  } while (0)
#endif

#endif
