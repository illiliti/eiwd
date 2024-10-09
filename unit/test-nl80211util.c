
#include <assert.h>
#include <ell/ell.h>
#include "src/nl80211util.h"
#include "linux/nl80211.h"

static void test_parse_attrs(const void *data)
{
	struct l_genl_msg *msg = l_genl_msg_new(NL80211_CMD_NEW_INTERFACE);
	uint32_t ifindex = 1;
	uint32_t freq = 2;
	int ret;

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &freq);

	ret = nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
					NL80211_ATTR_WIPHY_FREQ, &freq,
					NL80211_ATTR_UNSPEC);
	l_genl_msg_unref(msg);
	assert(ret == 0);
}

static void test_parse_nested(const void *data)
{
	struct l_genl_msg *msg = l_genl_msg_new(NL80211_CMD_NEW_INTERFACE);
	uint32_t ifindex = 1;
	uint32_t freq = 2;
	uint8_t noise = 3;
	uint8_t noise_out;
	struct l_genl_attr nested;
	int ret;
	int ret_nested;

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &freq);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_SURVEY_INFO);
	l_genl_msg_append_attr(msg, NL80211_SURVEY_INFO_NOISE, 1, &noise);
	l_genl_msg_leave_nested(msg);

	ret = nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
					NL80211_ATTR_WIPHY_FREQ, &freq,
					NL80211_ATTR_SURVEY_INFO, &nested,
					NL80211_ATTR_UNSPEC);
	ret_nested = nl80211_parse_nested(&nested, NL80211_ATTR_SURVEY_INFO,
					NL80211_SURVEY_INFO_NOISE, &noise_out,
					NL80211_ATTR_UNSPEC);
	l_genl_msg_unref(msg);
	assert(ret == 0);
	assert(ret_nested == 0);
	assert(noise_out == noise);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/nl80211util parse attrs", test_parse_attrs, NULL);
	l_test_add("/nl80211util parse nested", test_parse_nested, NULL);

	return l_test_run();
}
