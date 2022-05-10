/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: /usr/bin/gperf -L ANSI-C -t --ignore-case -N lookup_af -H hash_af_name -p -C src/basic/af-from-name.gperf  */
/* Computed positions: -k'4-5,7' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 1 "src/basic/af-from-name.gperf"

#if __GNUC__ >= 7
_Pragma("GCC diagnostic ignored \"-Wimplicit-fallthrough\"")
#endif
#line 6 "src/basic/af-from-name.gperf"
struct af_name { const char* name; int id; };

#define TOTAL_KEYWORDS 47
#define MIN_WORD_LENGTH 5
#define MAX_WORD_LENGTH 13
#define MIN_HASH_VALUE 6
#define MAX_HASH_VALUE 92
/* maximum key range = 87, duplicates = 0 */

#ifndef GPERF_DOWNCASE
#define GPERF_DOWNCASE 1
static unsigned char gperf_downcase[256] =
  {
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
     30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
     45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
     60,  61,  62,  63,  64,  97,  98,  99, 100, 101, 102, 103, 104, 105, 106,
    107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122,  91,  92,  93,  94,  95,  96,  97,  98,  99, 100, 101, 102, 103, 104,
    105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
    135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
    165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
    195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
    210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    255
  };
#endif

#ifndef GPERF_CASE_STRCMP
#define GPERF_CASE_STRCMP 1
static int
gperf_case_strcmp (register const char *s1, register const char *s2)
{
  for (;;)
    {
      unsigned char c1 = gperf_downcase[(unsigned char)*s1++];
      unsigned char c2 = gperf_downcase[(unsigned char)*s2++];
      if (c1 != 0 && c1 == c2)
        continue;
      return (int)c1 - (int)c2;
    }
}
#endif

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash_af_name (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      25, 93, 93, 15, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93,  0,  5, 35,  0,  5,
      40, 93, 15,  0, 93, 15, 15, 55,  5, 10,
       0,  0, 25,  5,  0, 40, 10,  5, 40, 93,
      93, 93, 93, 93, 93, 93, 93,  0,  5, 35,
       0,  5, 40, 93, 15,  0, 93, 15, 15, 55,
       5, 10,  0,  0, 25,  5,  0, 40, 10,  5,
      40, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93, 93, 93, 93, 93,
      93, 93, 93, 93, 93, 93
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[6]];
      /*FALLTHROUGH*/
      case 6:
      case 5:
        hval += asso_values[(unsigned char)str[4]];
      /*FALLTHROUGH*/
      case 4:
        hval += asso_values[(unsigned char)str[3]];
        break;
    }
  return hval;
}

const struct af_name *
lookup_af (register const char *str, register size_t len)
{
  static const struct af_name wordlist[] =
    {
      {(char*)0}, {(char*)0}, {(char*)0}, {(char*)0},
      {(char*)0}, {(char*)0},
#line 55 "src/basic/af-from-name.gperf"
      {"AF_IPX", AF_IPX},
      {(char*)0}, {(char*)0},
#line 48 "src/basic/af-from-name.gperf"
      {"AF_ATMPVC", AF_ATMPVC},
#line 12 "src/basic/af-from-name.gperf"
      {"AF_IB", AF_IB},
#line 49 "src/basic/af-from-name.gperf"
      {"AF_ASH", AF_ASH},
#line 34 "src/basic/af-from-name.gperf"
      {"AF_INET", AF_INET},
#line 18 "src/basic/af-from-name.gperf"
      {"AF_INET6", AF_INET6},
#line 37 "src/basic/af-from-name.gperf"
      {"AF_ATMSVC", AF_ATMSVC},
#line 19 "src/basic/af-from-name.gperf"
      {"AF_WANPIPE", AF_WANPIPE},
#line 43 "src/basic/af-from-name.gperf"
      {"AF_SNA", AF_SNA},
#line 53 "src/basic/af-from-name.gperf"
      {"AF_ISDN", AF_ISDN},
#line 29 "src/basic/af-from-name.gperf"
      {"AF_PPPOX", AF_PPPOX},
#line 51 "src/basic/af-from-name.gperf"
      {"AF_DECnet", AF_DECnet},
      {(char*)0},
#line 46 "src/basic/af-from-name.gperf"
      {"AF_ALG", AF_ALG},
      {(char*)0},
#line 39 "src/basic/af-from-name.gperf"
      {"AF_IEEE802154", AF_IEEE802154},
#line 38 "src/basic/af-from-name.gperf"
      {"AF_PACKET", AF_PACKET},
#line 42 "src/basic/af-from-name.gperf"
      {"AF_NETBEUI", AF_NETBEUI},
#line 31 "src/basic/af-from-name.gperf"
      {"AF_KEY", AF_KEY},
#line 11 "src/basic/af-from-name.gperf"
      {"AF_APPLETALK", AF_APPLETALK},
      {(char*)0},
#line 17 "src/basic/af-from-name.gperf"
      {"AF_PHONET", AF_PHONET},
      {(char*)0},
#line 28 "src/basic/af-from-name.gperf"
      {"AF_RDS", AF_RDS},
#line 40 "src/basic/af-from-name.gperf"
      {"AF_IRDA", AF_IRDA},
#line 45 "src/basic/af-from-name.gperf"
      {"AF_LOCAL", AF_LOCAL},
      {(char*)0},
#line 26 "src/basic/af-from-name.gperf"
      {"AF_NETLINK", AF_NETLINK},
#line 9 "src/basic/af-from-name.gperf"
      {"AF_LLC", AF_LLC},
#line 22 "src/basic/af-from-name.gperf"
      {"AF_BLUETOOTH", AF_BLUETOOTH},
      {(char*)0},
#line 20 "src/basic/af-from-name.gperf"
      {"AF_BRIDGE", AF_BRIDGE},
      {(char*)0},
#line 21 "src/basic/af-from-name.gperf"
      {"AF_CAN", AF_CAN},
#line 16 "src/basic/af-from-name.gperf"
      {"AF_TIPC", AF_TIPC},
#line 24 "src/basic/af-from-name.gperf"
      {"AF_ROUTE", AF_ROUTE},
#line 14 "src/basic/af-from-name.gperf"
      {"AF_NETROM", AF_NETROM},
#line 47 "src/basic/af-from-name.gperf"
      {"AF_QIPCRTR", AF_QIPCRTR},
#line 10 "src/basic/af-from-name.gperf"
      {"AF_XDP", AF_XDP},
#line 13 "src/basic/af-from-name.gperf"
      {"AF_ROSE", AF_ROSE},
      {(char*)0}, {(char*)0}, {(char*)0},
#line 23 "src/basic/af-from-name.gperf"
      {"AF_NFC", AF_NFC},
#line 15 "src/basic/af-from-name.gperf"
      {"AF_FILE", AF_FILE},
      {(char*)0},
#line 33 "src/basic/af-from-name.gperf"
      {"AF_ECONET", AF_ECONET},
      {(char*)0},
#line 30 "src/basic/af-from-name.gperf"
      {"AF_KCM", AF_KCM},
#line 32 "src/basic/af-from-name.gperf"
      {"AF_IUCV", AF_IUCV},
#line 44 "src/basic/af-from-name.gperf"
      {"AF_VSOCK", AF_VSOCK},
      {(char*)0}, {(char*)0},
#line 25 "src/basic/af-from-name.gperf"
      {"AF_SECURITY", AF_SECURITY},
#line 27 "src/basic/af-from-name.gperf"
      {"AF_AX25", AF_AX25},
      {(char*)0}, {(char*)0}, {(char*)0},
#line 36 "src/basic/af-from-name.gperf"
      {"AF_SMC", AF_SMC},
#line 35 "src/basic/af-from-name.gperf"
      {"AF_MPLS", AF_MPLS},
      {(char*)0}, {(char*)0}, {(char*)0},
#line 54 "src/basic/af-from-name.gperf"
      {"AF_X25", AF_X25},
      {(char*)0},
#line 41 "src/basic/af-from-name.gperf"
      {"AF_RXRPC", AF_RXRPC},
      {(char*)0}, {(char*)0}, {(char*)0}, {(char*)0},
      {(char*)0}, {(char*)0}, {(char*)0}, {(char*)0},
#line 52 "src/basic/af-from-name.gperf"
      {"AF_CAIF", AF_CAIF},
      {(char*)0}, {(char*)0}, {(char*)0}, {(char*)0},
      {(char*)0}, {(char*)0}, {(char*)0}, {(char*)0},
      {(char*)0},
#line 50 "src/basic/af-from-name.gperf"
      {"AF_UNIX", AF_UNIX}
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = hash_af_name (str, len);

      if (key <= MAX_HASH_VALUE)
        {
          register const char *s = wordlist[key].name;

          if (s && (((unsigned char)*str ^ (unsigned char)*s) & ~32) == 0 && !gperf_case_strcmp (str, s))
            return &wordlist[key];
        }
    }
  return 0;
}
