/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2015 Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "fchec.h"

void agesawrapper_fchecfancontrolservice(void)
{
	FCH_DATA_BLOCK LateParams;

	/* Thermal Zone Parameter */
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg0 = 0x00;
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg1 = 0x00; /* Zone */
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg2 = 0x3d;
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg3 = 0xc6;
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg4 = 0x00;
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg5 = 0x04;
	/* SMBUS Address for SMBUS based temperature sensor */
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg6 = 0x98;
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg7 = 0x01;
	/* PWM steping rate in unit of PWM level percentage */
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg8 = 0x01;
	LateParams.Imc.EcStruct.MsgFun81Zone0MsgReg9 = 0x00;

	/* IMC Fan Policy temperature thresholds */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg0 = 0x00;
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg1 = 0x00; /* Zone */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg2 = 0x3c; /*AC0 threshold */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg3 = 0x28; /*AC1 in oC */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg4 = 0xff; /*AC2 in oC */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg5 = 0xff; /*AC3 undefined */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg6 = 0xff; /*AC4 undefined */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg7 = 0xff; /*AC5 undefined */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg8 = 0xff; /*AC6 undefined */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgReg9 = 0xff; /*AC7 undefined */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgRegA = 0x4b; /*crit threshold */
	LateParams.Imc.EcStruct.MsgFun83Zone0MsgRegB = 0x00;

	/* IMC Fan Policy PWM Settings */
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg0 = 0x00;
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg1 = 0x00; /* Zone */
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg2 = 0x50; /* AL0 percent */
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg3 = 0x32; /* AL1 percent */
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg4 = 0xff; /* AL2 percent */
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg5 = 0xff; /* AL3 percent */
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg6 = 0xff; /* AL4 percent */
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg7 = 0xff; /* AL5 percent */
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg8 = 0xff; /* AL6 percent */
	LateParams.Imc.EcStruct.MsgFun85Zone0MsgReg9 = 0xff; /* AL7 percent */

	LateParams.Imc.EcStruct.IMCFUNSupportBitMap = 0x111;

	FchECfancontrolservice(&LateParams);
}
