#ifndef __AWINIC_CALI_FS_H__
#define __AWINIC_CALI_FS_H__

#include <linux/miscdevice.h>

#define AWINIC_ADSP_ENABLE
#define AW_CALI_STORE_EXAMPLE

/* default CALI RE */
#define DEFAULT_CALI_VALUE (7)

/*dsp params id*/
#define AFE_PARAM_ID_AWDSP_RX_SET_ENABLE		(0x10013D11)
#define AFE_PARAM_ID_AWDSP_RX_PARAMS			(0x10013D12)
#define AFE_PARAM_ID_AWDSP_TX_SET_ENABLE		(0x10013D13)
#define AFE_PARAM_ID_AWDSP_RX_VMAX_L			(0X10013D17)
#define AFE_PARAM_ID_AWDSP_RX_VMAX_R			(0X10013D18)
#define AFE_PARAM_ID_AWDSP_RX_CALI_CFG_L		(0X10013D19)
#define AFE_PARAM_ID_AWDSP_RX_CALI_CFG_R		(0x10013d1A)
#define AFE_PARAM_ID_AWDSP_RX_RE_L				(0x10013d1B)
#define AFE_PARAM_ID_AWDSP_RX_RE_R				(0X10013D1C)
#define AFE_PARAM_ID_AWDSP_RX_NOISE_L			(0X10013D1D)
#define AFE_PARAM_ID_AWDSP_RX_NOISE_R			(0X10013D1E)
#define AFE_PARAM_ID_AWDSP_RX_F0_L				(0X10013D1F)
#define AFE_PARAM_ID_AWDSP_RX_F0_R				(0X10013D20)
#define AFE_PARAM_ID_AWDSP_RX_REAL_DATA_L		(0X10013D21)
#define AFE_PARAM_ID_AWDSP_RX_REAL_DATA_R		(0X10013D22)

enum afe_param_id_awdsp {
	INDEX_PARAMS_ID_RX_PARAMS = 0,
	INDEX_PARAMS_ID_RX_ENBALE,
	INDEX_PARAMS_ID_TX_ENABLE,
	INDEX_PARAMS_ID_RX_VMAX,
	INDEX_PARAMS_ID_RX_CALI_CFG,
	INDEX_PARAMS_ID_RX_RE,
	INDEX_PARAMS_ID_RX_NOISE,
	INDEX_PARAMS_ID_RX_F0,
	INDEX_PARAMS_ID_RX_REAL_DATA,
	INDEX_PARAMS_ID_MAX
};

static const uint32_t PARAM_ID_INDEX_TABLE[][INDEX_PARAMS_ID_MAX] = {
	{
		AFE_PARAM_ID_AWDSP_RX_PARAMS,
		AFE_PARAM_ID_AWDSP_RX_SET_ENABLE,
		AFE_PARAM_ID_AWDSP_TX_SET_ENABLE,
		AFE_PARAM_ID_AWDSP_RX_VMAX_L,
		AFE_PARAM_ID_AWDSP_RX_CALI_CFG_L,
		AFE_PARAM_ID_AWDSP_RX_RE_L,
		AFE_PARAM_ID_AWDSP_RX_NOISE_L,
		AFE_PARAM_ID_AWDSP_RX_F0_L,
		AFE_PARAM_ID_AWDSP_RX_REAL_DATA_L,
	},
	{
		AFE_PARAM_ID_AWDSP_RX_PARAMS,
		AFE_PARAM_ID_AWDSP_RX_SET_ENABLE,
		AFE_PARAM_ID_AWDSP_TX_SET_ENABLE,
		AFE_PARAM_ID_AWDSP_RX_VMAX_R,
		AFE_PARAM_ID_AWDSP_RX_CALI_CFG_R,
		AFE_PARAM_ID_AWDSP_RX_RE_R,
		AFE_PARAM_ID_AWDSP_RX_NOISE_R,
		AFE_PARAM_ID_AWDSP_RX_F0_R,
		AFE_PARAM_ID_AWDSP_RX_REAL_DATA_R,
	},
};


#ifdef AWINIC_ADSP_ENABLE
extern int aw_send_afe_cal_apr(uint32_t param_id,
	void *buf, int cmd_size, bool write);
extern int aw_send_afe_rx_module_enable(void *buf, int size);
extern int aw_send_afe_tx_module_enable(void *buf, int size);
#else
static int aw_send_afe_cal_apr(uint32_t param_id,
	void *buf, int cmd_size, bool write)
{
	return 0;
}
int aw_send_afe_rx_module_enable(void *buf, int size)
{
	return 0;
}
int aw_send_afe_tx_module_enable(void *buf, int size)
{
	return 0;
}
#endif



/*********misc device ioctl fo cali**********/
#define AW882XX_CALI_CFG_NUM 3
#define AW882XX_CALI_DATA_NUM 6
#define AW882XX_PARAMS_NUM 400

struct cali_cfg {
	int32_t data[AW882XX_CALI_CFG_NUM];
};
struct cali_data {
	int32_t data[AW882XX_CALI_DATA_NUM];
};
struct params_data {
	int32_t data[AW882XX_PARAMS_NUM];
};

#define AW882XX_IOCTL_MAGIC					'a'
#define AW882XX_IOCTL_SET_CALI_CFG			_IOWR(AW882XX_IOCTL_MAGIC, 1, struct cali_cfg)
#define AW882XX_IOCTL_GET_CALI_CFG			_IOWR(AW882XX_IOCTL_MAGIC, 2, struct cali_cfg)
#define AW882XX_IOCTL_GET_CALI_DATA			_IOWR(AW882XX_IOCTL_MAGIC, 3, struct cali_data)
#define AW882XX_IOCTL_SET_NOISE				_IOWR(AW882XX_IOCTL_MAGIC, 4, int32_t)
#define AW882XX_IOCTL_GET_F0				_IOWR(AW882XX_IOCTL_MAGIC, 5, int32_t)
#define AW882XX_IOCTL_SET_CALI_RE			_IOWR(AW882XX_IOCTL_MAGIC, 6, int32_t)
#define AW882XX_IOCTL_GET_CALI_RE			_IOWR(AW882XX_IOCTL_MAGIC, 7, int32_t)
#define AW882XX_IOCTL_SET_VMAX				_IOWR(AW882XX_IOCTL_MAGIC, 8, int32_t)
#define AW882XX_IOCTL_GET_VMAX				_IOWR(AW882XX_IOCTL_MAGIC, 9, int32_t)
#define AW882XX_IOCTL_SET_PARAM				_IOWR(AW882XX_IOCTL_MAGIC, 10, struct params_data)
#define AW882XX_IOCTL_ENABLE_CALI			_IOWR(AW882XX_IOCTL_MAGIC, 11, int8_t)

struct aw_misc_cali {
	struct miscdevice misc_device;
};

struct aw_dbg_cali {
	struct dentry *dbg_dir;
	struct dentry *dbg_range;
	struct dentry *dbg_cali;
	struct dentry *dbg_status;
	struct dentry *dbg_f0;
};

enum{
	AW_CALI_MODE_NONE = 0,
	AW_CALI_MODE_DBGFS,
	AW_CALI_MODE_MISC,
	AW_CALI_MODE_MAX
};

struct aw_cali {
	unsigned char status;
	unsigned char cali_mode;
	int32_t cali_re;
	int32_t cali_f0;

	struct aw_dbg_cali dbg_fs;
	struct aw_misc_cali misc;
};


void aw_cali_init(struct aw_cali *cali);
void aw_cali_deinit(struct aw_cali *cali);

int aw_write_data_to_dsp(int index, void *data, int len, int channel);
int aw_read_data_to_dsp(int index, void *data, int len, int channel);

void aw882xx_load_cali_re(struct aw_cali *cali);


#endif
