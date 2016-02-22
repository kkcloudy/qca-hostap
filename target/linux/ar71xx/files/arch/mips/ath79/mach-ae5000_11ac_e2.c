/*
 * Qualcomm Atheros AP136 reference board support
 *
 * Copyright (c) 2012 Qualcomm Atheros
 * Copyright (c) 2012-2013 Gabor Juhos <juhosg@openwrt.org>
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
#include <linux/ar8216_platform.h>

#include <asm/mach-ath79/ar71xx_regs.h>

#include "common.h"
#include "pci.h"
#include "dev-ap9x-pci.h"
#include "dev-gpio-buttons.h"
#include "dev-eth.h"
#include "dev-leds-gpio.h"
#include "dev-m25p80.h"
#include "dev-nfc.h"
#include "dev-usb.h"
#include "dev-wmac.h"
#include "machtypes.h"

#define AE5000_11AC_E2_GPIO_BTN_RESET           17
#define AE5000_11AC_E2_GPIO_LED_STATUS_RED	4
#define AE5000_11AC_E2_GPIO_LED_STATUS_BLUE	13
#define AE5000_11AC_E2_GPIO_LED_STATUS_GREEN	 14
#define AE5000_11AC_E2_KEYS_POLL_INTERVAL	20	/* msecs */
#define AE5000_11AC_E2_KEYS_DEBOUNCE_INTERVAL	(3 * AE5000_11AC_E2_KEYS_POLL_INTERVAL)

#define AE5000_11AC_E2_MAC0_OFFSET		0
#define AE5000_11AC_E2_MAC1_OFFSET		6
#define AE5000_11AC_E2_WMAC_CALDATA_OFFSET	0x1000
#define AE5000_11AC_E2_PCIE_CALDATA_OFFSET	0x5000

static struct gpio_led ae5000_11ac_e2_leds_gpio[] __initdata = {
    {
    	.name		= "ae5000_11ac_e2:green:status",
    	.gpio		= AE5000_11AC_E2_GPIO_LED_STATUS_GREEN,
    	.active_low	= 0,
    },
    {
    	.name		= "ae5000_11ac_e2:red:status",
    	.gpio		= AE5000_11AC_E2_GPIO_LED_STATUS_RED,
    	.active_low	= 0,
	.default_state = LEDS_GPIO_DEFSTATE_ON,	
    },
    {
    	.name		= "ae5000_11ac_e2:blue:status",
    	.gpio		= AE5000_11AC_E2_GPIO_LED_STATUS_BLUE,
    	.active_low	= 0,
    },
};

static struct gpio_keys_button ae5000_11ac_e2_gpio_keys[] __initdata = {
	{
		.desc		= "reset",
		.type		= EV_KEY,
		.code		= KEY_RESTART,
		.debounce_interval = AE5000_11AC_E2_KEYS_DEBOUNCE_INTERVAL,
		.gpio		= AE5000_11AC_E2_GPIO_BTN_RESET,
		.active_low	= 1,
	},	
};

static struct ar8327_pad_cfg ae5000_11ac_e2_ar8327_pad0_cfg;
static struct ar8327_pad_cfg ae5000_11ac_e2_ar8327_pad6_cfg;

static struct ar8327_platform_data ae5000_11ac_e2_ar8327_data = {
	.pad0_cfg = &ae5000_11ac_e2_ar8327_pad0_cfg,
	.pad6_cfg = &ae5000_11ac_e2_ar8327_pad6_cfg,
	.port0_cfg = {
		.force_link = 1,
		.speed = AR8327_PORT_SPEED_1000,
		.duplex = 1,
		.txpause = 1,
		.rxpause = 1,
	},
	.port6_cfg = {
		.force_link = 1,
		.speed = AR8327_PORT_SPEED_1000,
		.duplex = 1,
		.txpause = 1,
		.rxpause = 1,
	},
};

static struct mdio_board_info ae5000_11ac_e2_mdio0_info[] = {
	{
		.bus_id = "ag71xx-mdio.0",
		.phy_addr = 0,
		.platform_data = &ae5000_11ac_e2_ar8327_data,
	},
};

static void __init ae5000_11ac_e2_common_setup(void)
{
	u8 *art = (u8 *) KSEG1ADDR(0x1fff0000);

	ath79_register_m25p80(NULL);

	ath79_register_leds_gpio(-1, ARRAY_SIZE(ae5000_11ac_e2_leds_gpio),
				 ae5000_11ac_e2_leds_gpio);
	ath79_register_gpio_keys_polled(-1, AE5000_11AC_E2_KEYS_POLL_INTERVAL,
					ARRAY_SIZE(ae5000_11ac_e2_gpio_keys),
					ae5000_11ac_e2_gpio_keys);

	ath79_register_usb();
	ath79_register_nfc();

	ath79_register_wmac(art + AE5000_11AC_E2_WMAC_CALDATA_OFFSET, NULL);

	ath79_setup_qca955x_eth_cfg(QCA955X_ETH_CFG_RGMII_EN);

	ath79_register_mdio(0, 0x0);

	ath79_init_mac(ath79_eth0_data.mac_addr, art + AE5000_11AC_E2_MAC0_OFFSET, 0);

	mdiobus_register_board_info(ae5000_11ac_e2_mdio0_info,
				    ARRAY_SIZE(ae5000_11ac_e2_mdio0_info));

	/* GMAC0 is connected to the RMGII interface */
	ath79_eth0_data.phy_if_mode = PHY_INTERFACE_MODE_RGMII;
	ath79_eth0_data.phy_mask = BIT(0);
	ath79_eth0_data.mii_bus_dev = &ath79_mdio0_device.dev;

	ath79_register_eth(0);

	/* GMAC1 is connected tot eh SGMII interface */
	ath79_eth1_data.phy_if_mode = PHY_INTERFACE_MODE_SGMII;
	ath79_eth1_data.speed = SPEED_1000;
	ath79_eth1_data.duplex = DUPLEX_FULL;

	ath79_register_eth(1);
}

static void __init ae5000_11ac_e2_setup(void)
{
	/* GMAC0 of the AR8327 switch is connected to GMAC1 via SGMII */
	ae5000_11ac_e2_ar8327_pad0_cfg.mode = AR8327_PAD_MAC_SGMII;
	ae5000_11ac_e2_ar8327_pad0_cfg.sgmii_delay_en = true;

	/* GMAC6 of the AR8327 switch is connected to GMAC0 via RGMII */
	ae5000_11ac_e2_ar8327_pad6_cfg.mode = AR8327_PAD_MAC_RGMII;
	ae5000_11ac_e2_ar8327_pad6_cfg.txclk_delay_en = true;
	ae5000_11ac_e2_ar8327_pad6_cfg.rxclk_delay_en = true;
	ae5000_11ac_e2_ar8327_pad6_cfg.txclk_delay_sel = AR8327_CLK_DELAY_SEL1;
	ae5000_11ac_e2_ar8327_pad6_cfg.rxclk_delay_sel = AR8327_CLK_DELAY_SEL2;

	ath79_eth0_pll_data.pll_1000 = 0x56000000;
	ath79_eth1_pll_data.pll_1000 = 0x03000101;

	ae5000_11ac_e2_common_setup();
	ath79_register_pci();
}

MIPS_MACHINE(ATH79_MACH_AE5000_11AC_E2, "AE5000_11AC_E2",
	     "Atheros AE5000_11AC_E2 reference board",
	     ae5000_11ac_e2_setup);
