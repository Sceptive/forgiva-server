#include "types.h"

#ifndef _HAVE_TEST_H
#define _HAVE_TEST_H

static int FORGIVA_GENERATION_TEST_COUNT = 9;

static forgiva_generation_test fg_tests[] = {

	
	/** facebook.com - bill.gates@microsoft.com **/
	{fstr("facebook.com"), fstr("bill.gates@microsoft.com"), fstr("1970-01-01"),
	fstr("forgiva_rockz_all_the_fuck1ng_t1m3"), FORGIVA_PG_SIMPLE, fstr("Ape"),
	fstr("797036592a475f78444c6153504d3757"),
		fstr("466b74674d645a4d6939302a6e56797a"),
		fstr("496e42574a46626a423938537a6c365a")
	},

	/** facebook.com - root **/
	{fstr("facebook.com"), fstr("root"), fstr("1970-01-01"),
	fstr("forgiva_rockz_all_the_fuck1ng_t1m3"), FORGIVA_PG_INTERMEDIATE,
	fstr("Bat"), fstr("5544245f2b72682e4635765040416a49"),
		fstr("354b223d3b6c246733386c2d6674283d"),
		fstr("65535c53773573554a38684f78306b30")

	},

	/** facebook.com - k3ym4k3r **/
	{fstr("facebook.com"), fstr("k3ym4k3r"), fstr("1970-01-01"),
	fstr("forgiva_rockz_all_the_fuck1ng_t1m3"), FORGIVA_PG_ADVANCED,
	fstr("Bear"), fstr("4f5c7653513251417a675949284c5539"),
		fstr("587a796a7c40267426637b694d345459"),
		fstr("71732f547957495c2f31384a79777974")

	},

	/** facebook.com - scr1ptk1dd1e **/
	{fstr("facebook.com"), fstr("scr1ptk1dd1e"), fstr("1970-01-01"),
	fstr("forgiva_rockz_all_the_fuck1ng_t1m3"), FORGIVA_PG_SIMPLE,
	fstr("Whale"), fstr("6465635a675374322f47695051464157"),
		fstr("496375392e63486a59434473334d6169"),
		fstr("506533703179666d6a4d563545593865")
	},

	/** microsoft.com - toor **/
	{fstr("microsoft.com"), fstr("toor"), fstr("1970-01-01"),
	fstr("forgiva_rockz_all_the_fuck1ng_t1m3"), FORGIVA_PG_INTERMEDIATE,
	fstr("Crow"), fstr("4d314573586d403649672970786d7133"),
		fstr("3e51542a4d364d31657673467c6d4728"),
		fstr("2a2f496c3c37666c644e2d333836535c")
	},

	/** 192.168.0.1 - root **/
	{fstr("192.168.0.1"), fstr("root"), fstr("1970-01-01"),
	fstr("forgiva_rockz_all_the_fuck1ng_t1m3"), FORGIVA_PG_ADVANCED,
	fstr("Dog"), fstr("2c376d234a7a6c4d6f785c34494a672a"),
		fstr("4939c2a232217c5c405a6c714e76552566"),
		fstr("543b2c5f2956382e436f49662a665738")

	},

	/** 10.0.0.2:22 - root **/
	{fstr("10.0.0.2:22"), fstr("root"), fstr("1970-01-01"),
	fstr("forgiva_rockz_all_the_fuck1ng_t1m3"), FORGIVA_PG_SIMPLE,
	fstr("Duck"), fstr("6440562a36375065693646396e312c4b"),
		fstr("345057425a5133756c5965745f7a7054"),
		fstr("75646f47406a6f412e394c6473554449")

	},

	/** 10.0.0.2:22 - k3ym4k3r **/
	{fstr("10.0.0.2:22"), fstr("k3ym4k3r"), fstr("1970-01-01"),
	fstr("forgiva_rockz_all_the_fuck1ng_t1m3"), FORGIVA_PG_INTERMEDIATE,
	fstr("Cat"), fstr("78435f57566e2f53535f2e617738293b"),
		fstr("5c624f23723e704673452530773e3144"),
		fstr("776c624d6e387c5c6f22676152763833")

	},

	/** 10.0.0.2:22 - toor **/
	{fstr("10.0.0.2:22"), fstr("toor"), fstr("1970-01-01"),
	fstr("forgiva_rockz_all_the_fuck1ng_t1m3"), FORGIVA_PG_ADVANCED,
	fstr("Wasp"), fstr("54534a582b265f337e2e43403b536861"),
		fstr("332b2541364e306537704e4551763938"),
		fstr("2a7d7b31407553304231597254326e69")

	}

};

static forgiva_algorithm_test fa_tests[] = {

	{true, fstr("camellia-128-cbc"),

	fstr("b9717e084ce3a6bb30af116bc811df7cbfdd618c005c92c90076162daba5a849"),
	fstr("d40d6d81d931ecc30a534c3f9d5dfe01"),
	fstr("cd5464cf4236b8a53ad5b42cbc27f0a8"),
	fstr("5a2e35425a955265856300246eca4e65a4a428935c80e59dffed50852b8430d0")},

	{true, fstr("camellia-192-cbc"),

	fstr("404e8c8b37e91d052ffd70573ed257a9677811cfa73458ba0607dc9e8def97b4"),
	fstr("edb8557b39e7e656148f850530950d8c"),
	fstr("a8708092b77bd94c6b1f0b8cf6b0afd8"),
	fstr("9b297587c3291ddc538ca02cdcd46476f60d45dcf655ebb4d1f7f072d1c514f7")},

	{true, fstr("camellia-256-cbc"),

	fstr("f266dad6764640de2e13902fb7c04fcd7f1c2e950ceb1b6559d1e620ea2cf39b"),
	fstr("4200c4cad8b47814a5ed84ab0141aaeb"),
	fstr("e0a054f34133aa2602db257fee1e7db1"),
	fstr("be84b266be13e13fc78a27c4ec86c4d7b70ecb26d8d1f6bbe247744f029eed19")},

	{true, fstr("cast5-cbc"),

	fstr("777de3b277bda18f668e3d152e820c1780355e3acd3c840b21f012dd5746c033"),
	fstr("896f94494198b4867715bfe43a85678a"),
	fstr("164cc12f57553024cf070a9bfe6e9d2e"),
	fstr("a302710f9e7baf1ce2b77a341db04ce1defb1ef60b3e0cf77b265f877f4acbe8")},

	{true, fstr("bf-cbc"),

	fstr("d487857248f982686da2f4f2089ed190e682e0e9121f60ed5e8e5be9ac5ef899"),
	fstr("bfb9ed5fb23e17e59d930d25eb530a2c"),
	fstr("5a112824d6ae4d9fef511706ec5c68eb"),
	fstr("8544fe775bd28d691ae13c4083ab43b0c0b84062cade9b166b516dbd65685263")},

	{true, fstr("aes-128-cbc"),

	fstr("63e319d3fb7f655479be7b4a1ef03853c590bda498514ce2a4810fe77bb85aa8aa"),
	fstr("117063a80532b561a8e9a5fc8d850365"),
	fstr("13b6cd9b3c664b0d573fbced0c331040"),
	fstr("f8102b04449eb1ce0048c67496cce3e3a8f1cdb8238d661caddd7ad7d0af2aa920b7"
		"d5f224ae50a492e2534a729ca1eb")},

	{true, fstr("aes-192-cbc"),
	fstr("ad67bfaeadab3c6500cbb59a3995a489b131c371bd20c4a55bfe3d7408d6d84b"),
	fstr("dbab5fe55cd0f37e33e4b875d861ceb3"),
	fstr("98044a639fcec92837b300394a709f2c"),
	fstr("5e439780e5f56b92911e6e60e7ce74b6c5a71cb197d77d99c0e931600c918c03")},

	{true, fstr("aes-256-cbc"),

	fstr("344e7b462a97d48431d68d315dea1a8b8fcfbe3d73a819471309597127aef5da"),
	fstr("24545749f13f8fb477c7d5046f490dcc"),
	fstr("a5276092d0645616bf8999d744580515"),
	fstr("c60682324e2b83886e17432c212d6690d44afb465a201055af151b44a3448068")},

	{false, fstr("sha512"),

	fstr("695904cb6bf6b74ab18852f70750139d78dbf7d46dda70ce67afac1de89fd2dd"),
	fstr(""), fstr(""),
	fstr("390e9d9c2a5483695a3707b509cd5a5948dea7221e5c3293b0a4eb4dc3c068811b27"
		"eef66adf569e268b2779cb77e35ee030918b7f3364e1882b2d524a96846c")},

	{false, fstr("sha384"),

	fstr("de9beb10c8d4208fc23eaeeda614fa6ecf8811e36d61fca957546c7649e561c1"),
	fstr(""), fstr(""),
	fstr("dbab1b89b069043585eeb67fdae2683ec1f5a2d4e721400a3b2335228f49444fb4a0"
		"e0509a55d28ffdc608db0bf8866e")},

	{false, fstr("sha256"),

	fstr("46142ed7236f2420f4bdac45192ba954da0ea56235c03886e4a2b528d60044da"),
	fstr(""), fstr(""),
	fstr("dccec513ea5995846df778bed02468e80ffcac06bd07d20eedbed3d367634492")},

	{false, fstr("sha224"),

	fstr("72f159ef70dee2db9e4ce0df16e19231bbacf4127ec97f430b546f838d82d173"),
	fstr(""), fstr(""),
	fstr("0673d0dd51f915d37baf9767dc24325ab9c2317a73a9ef022aa7911c561efd65")},

	{false, fstr("sha1"),

	fstr("5bb6f36326d34827a14df430bf809a14da00c27583bd33aee91edfe58b24708a"),
	fstr(""), fstr(""),
	fstr("f0ceb2b738be458cc0519e7a8b02c6c5cdc1c773687e1f6fb36642e2b87bfeca")},

	{false, fstr("sha"),

	fstr("a8f11175865f3f4dc543f558c282ec9b7b439bf818a77000adc9dee2199d43f5"),
	fstr(""), fstr(""),
	fstr("47e73858d52f91a9f5a3c798d8903a759834fb955544d01deaf55e1fc380e861")},

	{false, fstr("md5"),

	fstr("1b6bc2af8a57ccf15339f023863d35e5f35d13127622e2d03e008eb78188f772"),
	fstr(""), fstr(""),
	fstr("38806990d2b77c96d5776e3ec43cf2082d05d1de3285443444a67f984d3c2288")},

	{false, fstr("md4"),

	fstr("a64d8b2bbee2a8c820c16a14cfaea65d417decc309b3621e1bd5dc4769bb7c61"),
	fstr(""), fstr(""),
	fstr("354fde36aeadd1816b506956985eb7b05a5f9490ae96d88c7a1b3100a8a8d2bc")},

	{false, fstr("ripemd160"),

	fstr("7c2d9f56b35109f7cfdf554f70fdbf2bbff97a2244c0677820be6b38983c90ea"),
	fstr(""), fstr(""),
	fstr("aec3c24f17677cbeffdf1081af591aaa20e51d04e69da384bb65f1eefebbb1f5")},

	{false, fstr("argon2d"),
			// Password
		fstr("a64d8b2bbee2a8c820c16a14cfaea65d417decc309b3621e1bd5dc4769bb7c61"),
			// Salt
		fstr("6162636465666768616263646566676861626364656667686162636465666768"), fstr(""),
			// Target
		fstr("51da08821f55c9917a7b92891c0a0dfc2e9cef0c686db5fabbfbf5bdb4452259")}

};

static int FORGIVA_ALG_TEST_COUNT = 18;

f_bool forgiva_test_algorithms(forgiva_options *opts);

#endif
