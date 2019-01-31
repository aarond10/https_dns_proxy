#include "gtest/gtest.h"

extern "C" {
#include "utils.h"
}

TEST(utils, dn_name_compress) {
}

TEST(utils, dn_name_nocompress) {
  char name[] = "a.b.com.";
  char tmp[10];
  uint8_t buf[10];

  // Buffer bigger.
  strcpy(tmp, name);
  EXPECT_EQ(9, dn_name_nocompress(tmp, buf, 10));

  // Buffer too small.
  strcpy(tmp, name);
  EXPECT_EQ(-1, dn_name_nocompress(tmp, buf, 7));

  // Buffer exact size.
  strcpy(tmp, name);
  EXPECT_EQ(9, dn_name_nocompress(tmp, buf, 9));
  
  // Expected output.
  char exp[] = "\1a\1b\3com\0";
  EXPECT_TRUE(!memcmp(exp, buf, 9));
}

TEST(utils, b64) {
  char enc[] = "SGVsbG8hIDEyMzQ=";
  char dec[] = "Hello! 1234";
  uint8_t buf[32];
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(strlen(dec), b64dec(enc, buf, 32));
  EXPECT_STREQ(dec, (char *)buf);
}

TEST(utils, b32hex) {
  char enc[] = "3RL3ODP8D910939I655B97GAQU6VE1Q7";
  char dec[] = "\x1E\xEA\x3C\x37\x28\x6A\x42\x04\x8D\x32\x31\x4A\xB4\x9E\x0A\xD7\x8D\xF7\x07\x47";
  uint8_t buf[64];
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(strlen(dec), b32hexdec(enc, buf, 64));
  EXPECT_TRUE(!memcmp(buf, dec, sizeof(dec) - 1));
}

TEST(utils, hex) {
  char enc[] = "0102030405060708090A0B0C0D0E0F";
  char dec[] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
  uint8_t buf[64];
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(strlen(dec), hexdec(enc, buf, 64));
  EXPECT_TRUE(!memcmp(buf, dec, sizeof(dec) - 1));
}

TEST(utils, parse_time) {
  // Trivial cases.
  EXPECT_EQ(0,           parse_time("19700101000000"));  // epoch
  EXPECT_EQ(1,           parse_time("19700101000001"));  // +1S
  EXPECT_EQ(60,          parse_time("19700101000100"));  // +1M
  EXPECT_EQ(3600,        parse_time("19700101010000"));  // +1H
  EXPECT_EQ(86400,       parse_time("19700102000000"));  // +1d
  EXPECT_EQ(365*86400,   parse_time("19710101000000"));  // +1y
  // Note: 1972 is a leap year. Check before and after Feb.
  EXPECT_EQ(2*365*86400, parse_time("19720101000000"));  // +2y
  EXPECT_EQ(2*365*86400 + 86400 * (31 + 29), 
                         parse_time("19720301000000"));  // +2y2m
  EXPECT_EQ(3*365*86400 + 86400, 
                         parse_time("19730101000000"));  // +3y
  // Note: 2000 _IS_ a leap year (2000%400 == 0).
  EXPECT_EQ(30*365*86400 + 86400 * 7,   // 7 leap years.
                         parse_time("20000101000000"));  // +30y
  EXPECT_EQ(30*365*86400 + 86400 * (7 + 31 + 29), 
                         parse_time("20000301000000"));  // +30y2m
  EXPECT_EQ(31*365*86400 + 86400 * 8,
                         parse_time("20010101000000"));  // +30y2m
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
