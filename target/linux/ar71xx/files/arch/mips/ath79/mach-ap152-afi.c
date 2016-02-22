
/*
 * Autelan AP152_AFI reference board support
 *
 * Copyright (c) 2014 The Linux Foundation. All rights reserved.
 * Copyright (c) 2012 Gabor Juhos <juhosg@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <linux/platform_device.h>
#include <linux/ath9k_platform.h>
#include <linux/ar8216_platform.h>

#include <asm/mach-ath79/ar71xx_regs.h>

#include "common.h"
#include "dev-m25p80.h"
#include "machtypes.h"
#include "pci.h"
#include "dev-eth.h"
#include "dev-gpio-buttons.h"
#include "dev-leds-gpio.h"
#include "dev-spi.h"
#include "dev-usb.h"
#include "dev-wmac.h"


#define AP152_AFI_KEYS_POLL_INTERVAL        20     /* msecs */
#define AP152_AFI_KEYS_DEBOUNCE_INTERVAL    (3 * AP152_AFI_KEYS_POLL_INTERVAL)

#define AP152_AFI_GPIO_BTN_RESET           2

#define AP152_AFI_GPIO_LED_YELLOW          14
#define AP152_AFI_GPIO_LED_GREEN		    15
#define AP152_AFI_GPIO_LED_RED		        16
#define AP152_AFI_GPIO_LED_BLUE		    19

#define AP152_AFI_MAC0_OFFSET               0
#define AP152_AFI_MAC1_OFFSET               6
#define AP152_AFI_WMAC_CALDATA_OFFSET       0x1000

#define AP152_AFI_GPIO_MDC			3
#define AP152_AFI_GPIO_MDIO			4

/*Autelan-Begin: zhaoyang1 modifies for loading qca98xx cal data 2015-02-06*/
#define AP152_AFI_QCA98XX_CALDATA_OFFSET 0x4000
extern u8 art_for_qca98xx[16 * 1024];
/*Autelan-End: zhaoyang1 modifies for loading qca98xx cal data 2015-02-06*/

static struct gpio_led ap152_afi_leds_gpio[] __initdata = {
    {
    	.name		= "ap152_afi:yellow",
    	.gpio		= AP152_AFI_GPIO_LED_YELLOW,
    	.active_low	= 1,
    },
    {
    	.name		= "ap152_afi:green",
    	.gpio		= AP152_AFI_GPIO_LED_GREEN,
    	.active_low	= 1,
    },
    {
    	.name		= "ap152_afi:red",
    	.gpio		= AP152_AFI_GPIO_LED_RED,
    	.active_low	= 1,
    	.default_state = LEDS_GPIO_DEFSTATE_ON,
    },
    {
    	.name		= "ap152_afi:blue",
    	.gpio		= AP152_AFI_GPIO_LED_BLUE,
    	.active_low	= 1,
    },
};

static struct gpio_keys_button ap152_afi_gpio_keys[] __initdata = {
	{
		.desc		= "reset",
		.type		= EV_KEY,
		.code		= KEY_RESTART,
		.debounce_interval = AP152_AFI_KEYS_DEBOUNCE_INTERVAL,
		.gpio		= AP152_AFI_GPIO_BTN_RESET,
		.active_low	= 1,
	},
};

static struct ar8327_pad_cfg ap152_afi_ar8337_pad0_cfg = {
	.mode = AR8327_PAD_MAC_SGMII,
	.txclk_delay_en = true,
	.rxclk_delay_en = true,
	.txclk_delay_sel = AR8327_CLK_DELAY_SEL1,
	.rxclk_delay_sel = AR8327_CLK_DELAY_SEL2,
};

static struct ar8327_platform_data ap152_afi_ar8337_data = {
	.pad0_cfg = &ap152_afi_ar8337_pad0_cfg,
	.port0_cfg = {
		.force_link = 1,
		.speed = AR8327_PORT_SPEED_1000,
		.duplex = 1,
		.txpause = 1,
		.rxpause = 1,
	},
};

static struct mdio_board_info ap152_afi_mdio0_info[] = {
	{
		.bus_id = "ag71xx-mdio.0",
		.phy_addr = 0,
		.platform_data = &ap152_afi_ar8337_data,
	},
};

static void __init ap152_afi_mdio_setup(void)
{
	//ath79_gpio_output_select(AP152_AFI_GPIO_MDC, QCA9563_GPIO_OUT_MUX_GE0_MDC);
	//ath79_gpio_output_select(AP152_AFI_GPIO_MDIO, QCA9563_GPIO_OUT_MUX_GE0_MDO);

	ath79_register_mdio(0, 0x0);
}

static void __init ap152_afi_setup(void)
{

	u8 *art = (u8 *) KSEG1ADDR(0x1fff0000);

	ath79_register_m25p80(NULL);

	ath79_register_leds_gpio(-1, ARRAY_SIZE(ap152_afi_leds_gpio),
				 ap152_afi_leds_gpio);

	ath79_register_gpio_keys_polled(-1, AP152_AFI_KEYS_POLL_INTERVAL,
					ARRAY_SIZE(ap152_afi_gpio_keys),
					ap152_afi_gpio_keys);

	ap152_afi_mdio_setup();

	mdiobus_register_board_info(ap152_afi_mdio0_info,
				    ARRAY_SIZE(ap152_afi_mdio0_info));

	ath79_register_wmac(art + AP152_AFI_WMAC_CALDATA_OFFSET, NULL);
	memcpy(art_for_qca98xx, art + AP152_AFI_QCA98XX_CALDATA_OFFSET, sizeof(art_for_qca98xx)); //zhaoyang1 modifies for loading qca98xx cal data 2015-02-06
	ath79_register_pci();

	/* GMAC0 is connected to an AR8337 switch */
	ath79_init_mac(ath79_eth0_data.mac_addr, art + AP152_AFI_MAC0_OFFSET, 0);
	ath79_eth0_data.phy_if_mode = PHY_INTERFACE_MODE_SGMII;
	ath79_eth0_data.speed = SPEED_1000;
	ath79_eth0_data.duplex = DUPLEX_FULL;
	ath79_eth0_data.phy_mask = BIT(0);
	//ath79_eth0_data.force_link = 1;
	ath79_eth0_data.mii_bus_dev = &ath79_mdio0_device.dev;
	ath79_eth0_pll_data.pll_1000 = 0x06000000;
	ath79_register_eth(0);
}

MIPS_MACHINE(ATH79_MACH_AP152_AFI, "AP152_AFI", "Autelan AP152_AFI reference board",
	     ap152_afi_setup);
