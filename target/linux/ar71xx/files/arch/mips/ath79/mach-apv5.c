/*
 * Atheros APV5 reference board support
 *
 * Copyright (c) 2011 Qualcomm Atheros
 * Copyright (c) 2011-2012 Gabor Juhos <juhosg@openwrt.org>
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

#include <linux/pci.h>
#include <linux/phy.h>
#include <linux/platform_device.h>
#include <linux/ath9k_platform.h>
#include <linux/ar8216_platform.h>

#include <asm/mach-ath79/ar71xx_regs.h>

#include "common.h"
#include "dev-ap9x-pci.h"
#include "dev-eth.h"
#include "dev-gpio-buttons.h"
#include "dev-leds-gpio.h"
#include "dev-m25p80.h"
#include "dev-nfc.h"
#include "dev-spi.h"
#include "dev-usb.h"
#include "dev-wmac.h"
#include "machtypes.h"

#define APV5_GPIO_LED_WLAN_5G		15
#define APV5_GPIO_LED_WLAN_2G		16
#define APV5_GPIO_LED_STATUS		    17

#define APV5_GPIO_BTN_RESET		    4

#define APV5_KEYS_POLL_INTERVAL	20	/* msecs */
#define APV5_KEYS_DEBOUNCE_INTERVAL	(3 * APV5_KEYS_POLL_INTERVAL)

#define APV5_MAC0_OFFSET		0
#define APV5_MAC1_OFFSET		6
#define APV5_WMAC_CALDATA_OFFSET	0x1000
#define APV5_PCIE_CALDATA_OFFSET	0x5000

/*Autelan-Begin: zhaoyang1 modifies for loading qca98xx cal data 2015-02-06*/
#define APV5_QCA98XX_CALDATA_OFFSET 0x4000
extern u8 art_for_qca98xx[16 * 1024];
/*Autelan-End: zhaoyang1 modifies for loading qca98xx cal data 2015-02-06*/
static struct gpio_led apv5_leds_gpio[] __initdata = {
	{
		.name		= "apv5:green:status",
		.gpio		= APV5_GPIO_LED_STATUS,
		.active_low	= 1,
	},
	{
		.name		= "apv5:green:wlan-5g",
		.gpio		= APV5_GPIO_LED_WLAN_5G,
		.active_low	= 1,
	},
	{
		.name		= "apv5:green:wlan-2g",
		.gpio		= APV5_GPIO_LED_WLAN_2G,
		.active_low	= 1,
	},
};

static struct gpio_keys_button apv5_gpio_keys[] __initdata = {
	{
		.desc		= "reset",
		.type		= EV_KEY,
		.code		= KEY_RESTART,
		.debounce_interval = APV5_KEYS_DEBOUNCE_INTERVAL,
		.gpio		= APV5_GPIO_BTN_RESET,
		.active_low	= 1,
	},
};

static struct ar8327_pad_cfg apv5_ar8327_pad0_cfg = {
	.mode = AR8327_PAD_MAC_RGMII,
	.txclk_delay_en = true,
	.rxclk_delay_en = true,
	.txclk_delay_sel = AR8327_CLK_DELAY_SEL1,
	.rxclk_delay_sel = AR8327_CLK_DELAY_SEL2,
};

static struct ar8327_led_cfg apv5_ar8327_led_cfg = {
	.led_ctrl0 = 0x00000000,
	.led_ctrl1 = 0xc737c737,
	.led_ctrl2 = 0x00000000,
	.led_ctrl3 = 0x00c30c00,
	.open_drain = true,
};

static struct ar8327_platform_data apv5_ar8327_data = {
	.pad0_cfg = &apv5_ar8327_pad0_cfg,
	.port0_cfg = {
		.force_link = 1,
		.speed = AR8327_PORT_SPEED_1000,
		.duplex = 1,
		.txpause = 1,
		.rxpause = 1,
	},
	.led_cfg = &apv5_ar8327_led_cfg,
};

static struct mdio_board_info apv5_mdio0_info[] = {
	{
		.bus_id = "ag71xx-mdio.0",
		.phy_addr = 0,
		.platform_data = &apv5_ar8327_data,
	},
};

static void __init apv5_setup(void)
{
	u8 *art = (u8 *) KSEG1ADDR(0x1fff0000);

	//ath79_gpio_output_select(APV5_GPIO_LED_STATUS, AR934X_GPIO_OUT_GPIO);
	//ath79_gpio_output_select(APV5_GPIO_LED_WLAN_5G, AR934X_GPIO_OUT_GPIO);
	ath79_gpio_output_select(APV5_GPIO_LED_WLAN_2G, AR934X_GPIO_OUT_GPIO);

    ath79_register_m25p80(NULL);

	ath79_register_leds_gpio(-1, ARRAY_SIZE(apv5_leds_gpio),
				 apv5_leds_gpio);
	ath79_register_gpio_keys_polled(-1, APV5_KEYS_POLL_INTERVAL,
					ARRAY_SIZE(apv5_gpio_keys),
					apv5_gpio_keys);
	ath79_register_usb();
	//ath79_register_wmac(art + APV5_WMAC_CALDATA_OFFSET, NULL);
	ath79_register_wmac(art + APV5_WMAC_CALDATA_OFFSET, NULL);
	memcpy(art_for_qca98xx, art + APV5_QCA98XX_CALDATA_OFFSET, sizeof(art_for_qca98xx)); //zhaoyang1 modifies for loading qca98xx cal data 2015-02-06
	ap91_pci_init(art + APV5_PCIE_CALDATA_OFFSET, NULL);

	ath79_setup_ar934x_eth_cfg(AR934X_ETH_CFG_RGMII_GMAC0 |
				   AR934X_ETH_CFG_SW_ONLY_MODE);

	ath79_register_mdio(1, 0x0);
	ath79_register_mdio(0, 0x0);

	ath79_init_mac(ath79_eth0_data.mac_addr, art + APV5_MAC0_OFFSET, 0);

	mdiobus_register_board_info(apv5_mdio0_info,
				    ARRAY_SIZE(apv5_mdio0_info));

	/* GMAC0 is connected to an AR8327 switch */
	ath79_eth0_data.phy_if_mode = PHY_INTERFACE_MODE_RGMII;
	ath79_eth0_data.phy_mask = BIT(0);
	ath79_eth0_data.mii_bus_dev = &ath79_mdio0_device.dev;
	ath79_eth0_pll_data.pll_1000 = 0x06000000;
	ath79_register_eth(0);

#if 0
	/* GMAC1 is connected to the internal switch */
	ath79_init_mac(ath79_eth1_data.mac_addr, art + APV5_MAC1_OFFSET, 0);
	ath79_eth1_data.phy_if_mode = PHY_INTERFACE_MODE_GMII;
	ath79_eth1_data.speed = SPEED_1000;
	ath79_eth1_data.duplex = DUPLEX_FULL;
	ath79_register_eth(1);
#endif

	ath79_register_nfc();
}

MIPS_MACHINE(ATH79_MACH_APV5, "APV5", "Atheros APV5 reference board",
	     apv5_setup);
