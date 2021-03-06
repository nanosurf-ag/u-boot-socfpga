// SPDX-License-Identifier: GPL-2.0+
/*
 *  Copyright (C) 2012-2019 Altera Corporation <www.altera.com>
 */

#include <common.h>
#include <asm/io.h>
#include <asm/pl310.h>
#include <asm/u-boot.h>
#include <asm/utils.h>
#include <image.h>
#include <asm/arch/reset_manager.h>
#include <spl.h>
#include <asm/arch/system_manager.h>
#include <asm/arch/freeze_controller.h>
#include <asm/arch/clock_manager.h>
#include <asm/arch/scan_manager.h>
#include <asm/arch/sdram.h>
#include <asm/arch/scu.h>
#include <asm/arch/misc.h>
#include <asm/arch/nic301.h>
#include <asm/sections.h>
#include <fdtdec.h>
#include <watchdog.h>
#include <asm/arch/pinmux.h>
#include <asm/arch/fpga_manager.h>
#include <mmc.h>
#include <memalign.h>

#define FPGA_BUFSIZ	16 * 1024

DECLARE_GLOBAL_DATA_PTR;

static const struct socfpga_system_manager *sysmgr_regs =
	(struct socfpga_system_manager *)SOCFPGA_SYSMGR_ADDRESS;

u32 spl_boot_device(void)
{
	const u32 bsel = readl(&sysmgr_regs->bootinfo);

	switch (SYSMGR_GET_BOOTINFO_BSEL(bsel)) {
	case 0x1:	/* FPGA (HPS2FPGA Bridge) */
		return BOOT_DEVICE_RAM;
	case 0x2:	/* NAND Flash (1.8V) */
	case 0x3:	/* NAND Flash (3.0V) */
		socfpga_per_reset(SOCFPGA_RESET(NAND), 0);
		return BOOT_DEVICE_NAND;
	case 0x4:	/* SD/MMC External Transceiver (1.8V) */
	case 0x5:	/* SD/MMC Internal Transceiver (3.0V) */
		socfpga_per_reset(SOCFPGA_RESET(SDMMC), 0);
		socfpga_per_reset(SOCFPGA_RESET(DMA), 0);
		return BOOT_DEVICE_MMC1;
	case 0x6:	/* QSPI Flash (1.8V) */
	case 0x7:	/* QSPI Flash (3.0V) */
		socfpga_per_reset(SOCFPGA_RESET(QSPI), 0);
		return BOOT_DEVICE_SPI;
	default:
		printf("Invalid boot device (bsel=%08x)!\n", bsel);
		hang();
	}
}

#ifdef CONFIG_SPL_MMC_SUPPORT
u32 spl_boot_mode(const u32 boot_device)
{
  return MMCSD_MODE_RAW;
}
#endif

void spl_board_init(void)
{
	int ret;
	ALLOC_CACHE_ALIGN_BUFFER(char, buf, FPGA_BUFSIZ);

	/* enable console uart printing */
	preloader_console_init();
	WATCHDOG_RESET();

	arch_early_init_r();

	/* set backupmode value to default value */
	gd->backupmode = 0;

	ret = fpgamgr_program(buf, FPGA_BUFSIZ, 0, LOAD_PERIPHERAL);
	
	/* Ony load Core Image if SPL loaded Peripheral succesfully. 
	   Ignore also core image if in Backup Mode */
	if (ret == 0)
	{
		ret = fpgamgr_program(buf, FPGA_BUFSIZ, 0, LOAD_CORE);
	}

	/* Catch errors occuring while loading the data part of .rbf.
	   Force switching to backup. */
	if (ret < 0)
	{
		fpgamgr_program(buf, FPGA_BUFSIZ, 0, LOAD_BACKUP);
	}
	/* If the IOSSM/full FPGA is already loaded, start DDR */
	if (is_fpgamgr_early_user_mode() || is_fpgamgr_user_mode())
		ddr_calibration_sequence();
}

void board_init_f(ulong dummy)
{
	dcache_disable();

	socfpga_init_security_policies();
	socfpga_sdram_remap_zero();
	socfpga_pl310_clear();

	/* Assert reset to all except L4WD0, l4WD1 and L4TIMER0 */
	socfpga_per_reset_all();
	socfpga_watchdog_disable();

	spl_early_init();

	/* Configure the clock based on handoff */
	cm_basic_init(gd->fdt_blob);

#ifdef CONFIG_HW_WATCHDOG
	/* release watchdog 1 from reset */
	socfpga_reset_deassert_wd1();

	/* reconfigure and enable the watchdog */
	hw_watchdog_init();
	WATCHDOG_RESET();
#endif /* CONFIG_HW_WATCHDOG */

	config_dedicated_pins(gd->fdt_blob);
	WATCHDOG_RESET();
}

#if defined(CONFIG_SPL_LOAD_FIT) && (defined(CONFIG_SPL_SPI_LOAD) || \
	defined(CONFIG_SPL_NAND_SUPPORT))
struct image_header *spl_get_load_buffer(int offset, size_t size)
{
	if (gd->ram_size)
		return (struct image_header *)(gd->ram_size / 2);
	else
		return NULL;
}

int board_fit_config_name_match(const char *name)
{
	/* Just empty function now - can't decide what to choose */
	debug("%s: %s\n", __func__, name);

	return 0;
}
#endif
