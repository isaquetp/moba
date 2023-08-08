#ifndef _AW882XX_H_
#define _AW882XX_H_

#include "awinic_cali.h"
#include "awinic_monitor.h"

/*#define AW_DEBUG*/
/*
 * i2c transaction on Linux limited to 64k
 * (See Linux kernel documentation: Documentation/i2c/writing-clients)
*/
#define MAX_I2C_BUFFER_SIZE					65536

#define AW882XX_FLAG_START_ON_MUTE			(1 << 0)
#define AW882XX_FLAG_SKIP_INTERRUPTS		(1 << 1)
#define AW882XX_FLAG_SAAM_AVAILABLE			(1 << 2)
#define AW882XX_FLAG_STEREO_DEVICE			(1 << 3)
#define AW882XX_FLAG_MULTI_MIC_INPUTS		(1 << 4)

#define AW882XX_NUM_RATES					9
#define AW882XX_SYSST_CHECK_MAX				10
#define AW882XX_MODE_SHIFT_MAX				3

#define AW882XX_CFG_NAME_MAX    64

#define AW882XX_OPEN_PA		0
#define AW882XX_CLOSE_PA	1

enum aw882xx_channel_mode_dsp {
	AW882XX_CHANNLE_LEFT_MONO = 0,
	AW882XX_CHANNLE_RIGHT = 1,
};

enum aw882xx_init {
	AW882XX_INIT_ST = 0,
	AW882XX_INIT_OK = 1,
	AW882XX_INIT_NG = 2,
};

enum aw882xx_chipid {
	AW882XX_ID = 0x1852,
};

enum aw882xx_modeshift {
	AW882XX_MODE_SPK_SHIFT = 0,
	AW882XX_MODE_RCV_SHIFT = 1,
	AW882XX_MODE_HANDFREE_SHIFT = 2,
};

enum aw882xx_mode_spk_rcv {
	AW882XX_SPEAKER_MODE = 0,
	AW882XX_RECEIVER_MODE = 1,
	AW882XX_HANDFREE_MODE = 2,
	AW882XX_OFF_MODE = 3,
};

struct aw882xx_chan_info{
	unsigned int channel;
	char *name_suffix;
	char (*bin_cfg_name)[AW882XX_CFG_NAME_MAX];
};

struct aw882xx_kctrl {
	int aw882xx_spk_rcv_control;
	int aw882xx_pa_switch;
};

struct aw882xx {
	int sysclk;
	int rate;
	int pstream;
	int cstream;

	int reset_gpio;
	int irq_gpio;

	unsigned char reg_addr;

	unsigned int mute_flags;

	unsigned int flags;
	unsigned int chipid;
	unsigned int init;
	unsigned int spk_rcv_mode;
	unsigned int cfg_num;

	struct regmap *regmap;
	struct i2c_client *i2c;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
	struct snd_soc_component *codec;
#else
	struct snd_soc_codec *codec;
#endif
	struct device *dev;
	struct mutex lock;

	struct aw882xx_chan_info chan_info;
	struct aw_cali cali;
	struct aw882xx_monitor monitor;
	struct aw882xx_kctrl aw882xx_kctrl;
};

struct aw882xx_container {
	int len;
	unsigned char data[];
};


#define aw_dev_err(dev, format, ...) \
			pr_err("[%s]" format, dev_name(dev), ##__VA_ARGS__)

#define aw_dev_info(dev, format, ...) \
			pr_info("[%s]" format, dev_name(dev), ##__VA_ARGS__)

#define aw_dev_dbg(dev, format, ...) \
			pr_debug("[%s]" format, dev_name(dev), ##__VA_ARGS__)


int aw882xx_i2c_write(struct aw882xx *aw882xx,
	unsigned char reg_addr, unsigned int reg_data);
int aw882xx_i2c_read(struct aw882xx *aw882xx,
	unsigned char reg_addr, unsigned int *reg_data);

void aw882xx_append_channel(char *format, const char **change_name,
	struct aw882xx *aw882xx);

void aw882xx_smartpa_cfg(struct aw882xx *aw882xx, bool flag);

void aw882xx_append_suffix(char *format, const char **change_name,
		struct aw882xx *aw882xx);

int aw882xx_db_to_reg_val(struct aw882xx *aw882xx,
				uint8_t db, uint32_t *reg_val);
int aw882xx_reg_val_to_db(struct aw882xx *aw882xx,
				uint8_t *db, uint32_t reg_val);
#endif
