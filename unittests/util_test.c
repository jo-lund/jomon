#include <gtest/gtest.h>
#include "../util.c"
#include "../vector.c"

TEST(hex_test, false_input)
{
    unsigned char num[6];

    EXPECT_FALSE(hextoint(num, ""));
    EXPECT_FALSE(hextoint(num, "::::"));
    EXPECT_FALSE(hextoint(num, ":23:23"));
    EXPECT_FALSE(hextoint(num, "1:af:23"));
    EXPECT_FALSE(hextoint(num, "12:13:14:15:h"));
    EXPECT_FALSE(hextoint(num, "12:13:14:15:"));
    EXPECT_FALSE(hextoint(num, "aabbccddeeff"));
    EXPECT_FALSE(hextoint(num, "12:13:14:15:ef:"));
    EXPECT_FALSE(hextoint(num, "12:13:14:15:ef:aa"));
    EXPECT_FALSE(hextoint(num, ""));
}

TEST(hex_test, true_input)
{
    unsigned char num[6];

    EXPECT_TRUE(hextoint(num, "00:18:e7:e7:6d:2a"));
    EXPECT_TRUE(hextoint(num, "11:aa:22:bb:33:cc"));
    EXPECT_TRUE(hextoint(num, "00:00:00:00:00:00"));
    EXPECT_TRUE(hextoint(num, "00:01:02:03:04:05"));
    EXPECT_TRUE(hextoint(num, "a1:b2:c3:d4:e5:f0"));
    EXPECT_TRUE(hextoint(num, "a0:00:c3:0c:e5:f0"));
    EXPECT_TRUE(hextoint(num, "00:00:c3:0c:e5:f0"));
}

TEST(vector_test, insertion)
{
    char *a = (char *) malloc(11);
    char *b = (char *) malloc(11);

    vector_init(2);
    for (int i = 0; i < 10; i++) {
        a[i] = 'a';
    }
    a[10] = '\0';
    for (int i = 0; i < 10; i++) {
        b[i] = 'b';
    }
    b[10] = '\0';
    vector_push_back(a);
    vector_push_back(b);
    EXPECT_STREQ("aaaaaaaaaa", (const char *) vector_get_data(0));
    EXPECT_STREQ("bbbbbbbbbb", (const char *) vector_get_data(1));
    vector_clear();
}
