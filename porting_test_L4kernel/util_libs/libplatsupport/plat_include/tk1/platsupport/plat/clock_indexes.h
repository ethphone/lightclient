/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#pragma once

/* Register information sourced from "NVIDIA Tegra K1 Mobile Processor TECHNICAL REFERENCE MANUAL" */

#define CLK_ENB_CPU 0
/* 1 */
/* 2 */
#define CLK_ENB_ISPB 3
#define CLK_ENB_RTC 4 /* Enabled on reset */
#define CLK_ENB_TMR 5 /* Enabled on reset */
#define CLK_ENB_UARTA 6
#define CLK_ENB_UARTB 7 /*UARTB/VFIR*/
#define CLK_ENB_GPIO 8 /* Enabled on reset */
#define CLK_ENB_SDMMC2 9
#define CLK_ENB_SPDIF 10
#define CLK_ENB_I2S1 11
#define CLK_ENB_I2C1 12
/* 13 */
#define CLK_ENB_SDMMC1 14
#define CLK_ENB_SDMMC4 15
/* 16 */
#define CLK_ENB_PWM 17
#define CLK_ENB_I2S2 18
/* 19 */
#define CLK_ENB_VI 20
/* 21 */
#define CLK_ENB_USBD 22
#define CLK_ENB_ISP 23
/* 24 */
/* 25 */
#define CLK_ENB_DISP2 26
#define CLK_ENB_DISP1 27
#define CLK_ENB_HOST1X 28
#define CLK_ENB_VCP 29
#define CLK_ENB_I2S0 30
#define CLK_ENB_CACHE2 31 /* Enabled on reset */

#define CLK_ENB_MEM 32
#define CLK_ENB_AHBDMA 33
#define CLK_ENB_APBDMA 34
/* 35 */
#define CLK_ENB_KBC 36
#define CLK_ENB_STAT_MON 37
#define CLK_ENB_PMC 38
#define CLK_ENB_FUSE 39 /* Enabled on reset */
#define CLK_ENB_KFUSE 40
#define CLK_ENB_SPI1 41
#define CLK_ENB_SNOR 42 /* Enabled on reset */
#define CLK_ENB_JTAG2TBC 43 /* Enabled on reset */
#define CLK_ENB_SPI2 44
/* 45 */
#define CLK_ENB_SPI3 46
#define CLK_ENB_I2C5 47
#define CLK_ENB_DSI 48
/* 49 */
#define CLK_ENB_HSI 50
#define CLK_ENB_HDMI 51
#define CLK_ENB_CSI 52
/* 53 */
#define CLK_ENB_I2C2 54
#define CLK_ENB_UARTC 55
#define CLK_ENB_MIPI_CAL 56
#define CLK_ENB_EMC 57
#define CLK_ENB_USB2 58
#define CLK_ENB_USB3 59
/* 60 */
#define CLK_ENB_VDE 61
#define CLK_ENB_BSEA 62
#define CLK_ENB_BSEV 63

/* 64 */
#define CLK_ENB_UARTD 65
/* 66 */
#define CLK_ENB_I2C3 67
#define CLK_ENB_SPI4 68
#define CLK_ENB_SDMMC3 69
#define CLK_ENB_PCIE 70
#define CLK_ENB_OWR 71
#define CLK_ENB_AFI 72
#define CLK_ENB_CSITE 73 /* Enabled on reset */
/* 74 */
#define CLK_ENB_AVPUCQ 75 /* Enabled on reset */
//#define CLK_ENB_LA 76
#define CLK_ENB_TRACECLKIN 77 /* Enabled on reset */
#define CLK_ENB_SOC_THERM 78
#define CLK_ENB_DTV 79
/* 80 */
#define CLK_ENB_I2C_SLOW 81
#define CLK_ENB_DSIB 82
#define CLK_ENB_TSEC 83
#define CLK_ENB_IRAMA 84 /* Enabled on reset */
#define CLK_ENB_IRAMB 85 /* Enabled on reset */
#define CLK_ENB_IRAMC 86 /* Enabled on reset */
#define CLK_ENB_IRAMD 87 /* Enabled on reset */
#define CLK_ENB_CRAM2 88 /* Enabled on reset */
#define CLK_ENB_XUSB_HOST 89
#define CLK_M_DOUBLER_ENB 90 /* Enabled on reset */
#define CLK_ENB_MSENC 91
#define CLK_ENB_SUS_OUT 92
#define CLK_ENB_DEV2_OUT 93
#define CLK_ENB_DEV1_OUT 94
#define CLK_ENB_XUSB_DEV 95

#define CLK_ENB_CPUG 96
#define CLK_ENB_CPULP 97
/* 98 */
#define CLK_ENB_MSELECT 99
#define CLK_ENB_TSENSOR 100
#define CLK_ENB_I2S3 101
#define CLK_ENB_I2S4 102
#define CLK_ENB_I2C4 103
#define CLK_ENB_SPI5 104
#define CLK_ENB_SPI6 105
#define CLK_ENB_AUDIO 106
#define CLK_ENB_APBIF 107
#define CLK_ENB_DAM0 108
#define CLK_ENB_DAM1 109
#define CLK_ENB_DAM2 110
#define CLK_ENB_HDA2CODEC_2X 111
#define CLK_ENB_ATOMICS 112
// #define CLK_ENB_AUDIO0_2X 113 Not in manual?
// #define CLK_ENB_AUDIO1_2X 114
// #define CLK_ENB_AUDIO2_2X 115
// #define CLK_ENB_AUDIO3_2X 116
// #define CLK_ENB_AUDIO4_2X 117
#define CLK_ENB_SPDIF_DOUBLER 118 /* Enabled on reset */
#define CLK_ENB_ACTMON 119
#define CLK_ENB_EXTPERIPH1 120
#define CLK_ENB_EXTPERIPH2 121
#define CLK_ENB_EXTPERIPH3 122
#define CLK_ENB_SATA_OOB 123
#define CLK_ENB_SATA 124
#define CLK_ENB_HDA 125
/* 126 */
// #define CLK_ENB_SE 127  Not in manual?

#define CLK_ENB_HDA2HDMICODEC 128
#define CLK_ENB_RESERVED0 129
#define CLK_ENB_PCIERX0 130 /* Enabled on reset, CLK_ENB_PCIE is master */
#define CLK_ENB_PCIERX1 131 /* Enabled on reset, CLK_ENB_PCIE is master */
#define CLK_ENB_PCIERX2 132 /* Enabled on reset, CLK_ENB_PCIE is master */
#define CLK_ENB_PCIERX3 133 /* Enabled on reset, CLK_ENB_PCIE is master */
#define CLK_ENB_PCIERX4 134 /* Enabled on reset, CLK_ENB_PCIE is master */
#define CLK_ENB_PCIERX5 135 /* Enabled on reset, CLK_ENB_PCIE is master */
#define CLK_ENB_CEC 136
#define CLK_ENB_PCIE2_IOBIST 137
#define CLK_ENB_EMC_IOBIST 138
#define CLK_ENB_HDMI_IOBIST 139
#define CLK_ENB_SATA_IOBIST 140
#define CLK_ENB_MIPI_IOBIST 141
/* 142 */
#define CLK_ENB_XUSB 143
#define CLK_ENB_CILAB 144
#define CLK_ENB_CILCD 145
#define CLK_ENB_CILE 146
#define CLK_ENB_DSIA_LP 147
#define CLK_ENB_DSIB_LP 148
#define CLK_ENB_ENTROPY 149 /* Enabled on reset */
// #define CLK_ENB_DDS 150 Not in manual?
/* 151 */
// #define CLK_ENB_DP2 152 Not in manual?
#define CLK_ENB_AMX0 153
#define CLK_ENB_ADX0 154
#define CLK_ENB_DVFS 155
#define CLK_ENB_XUSB_SS 156
#define CLK_ENB_EMC_LATENCY 157
/* 158 */
/* 159 */

#define CLK_ENB_SPARE 160
/* 161 */
/* 162 */
/* 163 */
#define CLK_ENB_CAM_MCLK 164
#define CLK_ENB_CAM_MCLK2 165
#define CLK_ENB_I2C6 166
/* 167 */
/* 168 */
/* 169 */
/* 170 */
#define CLK_ENB_VIM2_CLK 171
/* 172 */
/* 173 */
#define CLK_ENB_EMC_DLL 174
/* 175 */
#define CLK_ENB_HDMI_AUDIO 176
#define CLK_ENB_CLK72MHZ 177
#define CLK_ENB_VIC 178
/* 179 */
#define CLK_ENB_ADX1 180
#define CLK_ENB_DPAUX 181
#define CLK_ENB_SOR0 182
/* 183 */
#define CLK_ENB_GPU 184
#define CLK_ENB_AMX1 185
/* 186 */
/* 187 */
/* 188 */
/* 189 */
/* 190 */
/* 191 */

/* These are passed as arguments to clk_gate_enable(). */
enum clock_gate {
    CLK_GATE_CPU,
    CLK_GATE_ISPB,
    CLK_GATE_RTC, /* Enabled on reset */
    CLK_GATE_TMR, /* Enabled on reset */
    CLK_GATE_UARTA,
    CLK_GATE_UARTB, /*UARTB/VFIR*/
    CLK_GATE_GPIO, /* Enabled on reset */
    CLK_GATE_SDMMC2,
    CLK_GATE_SPDIF,
    CLK_GATE_I2S1,
    CLK_GATE_I2C1,
    CLK_GATE_SDMMC1,
    CLK_GATE_SDMMC4,
    CLK_GATE_PWM,
    CLK_GATE_I2S2,
    CLK_GATE_VI,
    CLK_GATE_USBD,
    CLK_GATE_ISP,
    CLK_GATE_DISP2,
    CLK_GATE_DISP1,
    CLK_GATE_HOST1X,
    CLK_GATE_VCP,
    CLK_GATE_I2S0,
    CLK_GATE_CACHE2, /* Enabled on reset */
    CLK_GATE_MEM,
    CLK_GATE_AHBDMA,
    CLK_GATE_APBDMA,
    CLK_GATE_KBC,
    CLK_GATE_STAT_MON,
    CLK_GATE_PMC,
    CLK_GATE_FUSE, /* Enabled on reset */
    CLK_GATE_KFUSE,
    CLK_GATE_SPI1,
    CLK_GATE_SNOR, /* Enabled on reset */
    CLK_GATE_JTAG2TBC, /* Enabled on reset */
    CLK_GATE_SPI2,
    CLK_GATE_SPI3,
    CLK_GATE_I2C5,
    CLK_GATE_DSI,
    CLK_GATE_HSI,
    CLK_GATE_HDMI,
    CLK_GATE_CSI,
    CLK_GATE_I2C2,
    CLK_GATE_UARTC,
    CLK_GATE_MIPI_CAL,
    CLK_GATE_EMC,
    CLK_GATE_USB2,
    CLK_GATE_USB3,
    CLK_GATE_VDE,
    CLK_GATE_BSEA,
    CLK_GATE_BSEV,
    CLK_GATE_UARTD,
    CLK_GATE_I2C3,
    CLK_GATE_SPI4,
    CLK_GATE_SDMMC3,
    CLK_GATE_PCIE,
    CLK_GATE_OWR,
    CLK_GATE_AFI,
    CLK_GATE_CSITE, /* Enabled on reset */
    CLK_GATE_AVPUCQ, /* Enabled on reset */
    CLK_GATE_TRACECLKIN, /* Enabled on reset */
    CLK_GATE_SOC_THERM,
    CLK_GATE_DTV,
    CLK_GATE_I2C_SLOW,
    CLK_GATE_DSIB,
    CLK_GATE_TSEC,
    CLK_GATE_IRAMA, /* Enabled on reset */
    CLK_GATE_IRAMB, /* Enabled on reset */
    CLK_GATE_IRAMC, /* Enabled on reset */
    CLK_GATE_IRAMD, /* Enabled on reset */
    CLK_GATE_CRAM2, /* Enabled on reset */
    CLK_GATE_XUSB_HOST,
    CLK_GATE_M_DOUBLER_ENB, /* Enabled on reset */
    CLK_GATE_MSENC,
    CLK_GATE_SUS_OUT,
    CLK_GATE_DEV2_OUT,
    CLK_GATE_DEV1_OUT,
    CLK_GATE_XUSB_DEV,
    CLK_GATE_CPUG,
    CLK_GATE_CPULP,
    CLK_GATE_MSELECT,
    CLK_GATE_TSENSOR,
    CLK_GATE_I2S3,
    CLK_GATE_I2S4,
    CLK_GATE_I2C4,
    CLK_GATE_SPI5,
    CLK_GATE_SPI6,
    CLK_GATE_AUDIO,
    CLK_GATE_APBIF,
    CLK_GATE_DAM0,
    CLK_GATE_DAM1,
    CLK_GATE_DAM2,
    CLK_GATE_HDA2CODEC_2X,
    CLK_GATE_ATOMICS,
    CLK_GATE_SPDIF_DOUBLER, /* Enabled on reset */
    CLK_GATE_ACTMON,
    CLK_GATE_EXTPERIPH1,
    CLK_GATE_EXTPERIPH2,
    CLK_GATE_EXTPERIPH3,
    CLK_GATE_SATA_OOB,
    CLK_GATE_SATA,
    CLK_GATE_HDA,
    CLK_GATE_HDA2HDMICODEC,
    CLK_GATE_RESERVED0,
    CLK_GATE_PCIERX0, /* Enabled on reset, CLK_GATE_PCIE is master */
    CLK_GATE_PCIERX1, /* Enabled on reset, CLK_GATE_PCIE is master */
    CLK_GATE_PCIERX2, /* Enabled on reset, CLK_GATE_PCIE is master */
    CLK_GATE_PCIERX3, /* Enabled on reset, CLK_GATE_PCIE is master */
    CLK_GATE_PCIERX4, /* Enabled on reset, CLK_GATE_PCIE is master */
    CLK_GATE_PCIERX5, /* Enabled on reset, CLK_GATE_PCIE is master */
    CLK_GATE_CEC,
    CLK_GATE_PCIE2_IOBIST,
    CLK_GATE_EMC_IOBIST,
    CLK_GATE_HDMI_IOBIST,
    CLK_GATE_SATA_IOBIST,
    CLK_GATE_MIPI_IOBIST,
    CLK_GATE_XUSB,
    CLK_GATE_CILAB,
    CLK_GATE_CILCD,
    CLK_GATE_CILE,
    CLK_GATE_DSIA_LP,
    CLK_GATE_DSIB_LP,
    CLK_GATE_ENTROPY, /* Enabled on reset */
    CLK_GATE_AMX0,
    CLK_GATE_ADX0,
    CLK_GATE_DVFS,
    CLK_GATE_XUSB_SS,
    CLK_GATE_EMC_LATENCY,
    CLK_GATE_SPARE,
    CLK_GATE_CAM_MCLK,
    CLK_GATE_CAM_MCLK2,
    CLK_GATE_I2C6,
    CLK_GATE_VIM2_CLK,
    CLK_GATE_EMC_DLL,
    CLK_GATE_HDMI_AUDIO,
    CLK_GATE_CLK72MHZ,
    CLK_GATE_VIC,
    CLK_GATE_ADX1,
    CLK_GATE_DPAUX,
    CLK_GATE_SOR0,
    CLK_GATE_GPU,
    CLK_GATE_AMX1,

    NCLKGATES
};
