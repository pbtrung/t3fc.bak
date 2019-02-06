/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "aria.h"
#include <memory.h>
#include <algorithm>
#include "portability.h"

#ifdef _MSC_VER
#define inline __forceinline
#endif

//#define CPPCRYPTO_DEBUG

namespace cppcrypto
{
	static const uint32_t T[4][256] = {
		{
			0x00636363, 0x007c7c7c, 0x00777777, 0x007b7b7b, 0x00f2f2f2, 0x006b6b6b, 0x006f6f6f, 0x00c5c5c5,
			0x00303030, 0x00010101, 0x00676767, 0x002b2b2b, 0x00fefefe, 0x00d7d7d7, 0x00ababab, 0x00767676,
			0x00cacaca, 0x00828282, 0x00c9c9c9, 0x007d7d7d, 0x00fafafa, 0x00595959, 0x00474747, 0x00f0f0f0,
			0x00adadad, 0x00d4d4d4, 0x00a2a2a2, 0x00afafaf, 0x009c9c9c, 0x00a4a4a4, 0x00727272, 0x00c0c0c0,
			0x00b7b7b7, 0x00fdfdfd, 0x00939393, 0x00262626, 0x00363636, 0x003f3f3f, 0x00f7f7f7, 0x00cccccc,
			0x00343434, 0x00a5a5a5, 0x00e5e5e5, 0x00f1f1f1, 0x00717171, 0x00d8d8d8, 0x00313131, 0x00151515,
			0x00040404, 0x00c7c7c7, 0x00232323, 0x00c3c3c3, 0x00181818, 0x00969696, 0x00050505, 0x009a9a9a,
			0x00070707, 0x00121212, 0x00808080, 0x00e2e2e2, 0x00ebebeb, 0x00272727, 0x00b2b2b2, 0x00757575,
			0x00090909, 0x00838383, 0x002c2c2c, 0x001a1a1a, 0x001b1b1b, 0x006e6e6e, 0x005a5a5a, 0x00a0a0a0,
			0x00525252, 0x003b3b3b, 0x00d6d6d6, 0x00b3b3b3, 0x00292929, 0x00e3e3e3, 0x002f2f2f, 0x00848484,
			0x00535353, 0x00d1d1d1, 0x00000000, 0x00ededed, 0x00202020, 0x00fcfcfc, 0x00b1b1b1, 0x005b5b5b,
			0x006a6a6a, 0x00cbcbcb, 0x00bebebe, 0x00393939, 0x004a4a4a, 0x004c4c4c, 0x00585858, 0x00cfcfcf,
			0x00d0d0d0, 0x00efefef, 0x00aaaaaa, 0x00fbfbfb, 0x00434343, 0x004d4d4d, 0x00333333, 0x00858585,
			0x00454545, 0x00f9f9f9, 0x00020202, 0x007f7f7f, 0x00505050, 0x003c3c3c, 0x009f9f9f, 0x00a8a8a8,
			0x00515151, 0x00a3a3a3, 0x00404040, 0x008f8f8f, 0x00929292, 0x009d9d9d, 0x00383838, 0x00f5f5f5,
			0x00bcbcbc, 0x00b6b6b6, 0x00dadada, 0x00212121, 0x00101010, 0x00ffffff, 0x00f3f3f3, 0x00d2d2d2,
			0x00cdcdcd, 0x000c0c0c, 0x00131313, 0x00ececec, 0x005f5f5f, 0x00979797, 0x00444444, 0x00171717,
			0x00c4c4c4, 0x00a7a7a7, 0x007e7e7e, 0x003d3d3d, 0x00646464, 0x005d5d5d, 0x00191919, 0x00737373,
			0x00606060, 0x00818181, 0x004f4f4f, 0x00dcdcdc, 0x00222222, 0x002a2a2a, 0x00909090, 0x00888888,
			0x00464646, 0x00eeeeee, 0x00b8b8b8, 0x00141414, 0x00dedede, 0x005e5e5e, 0x000b0b0b, 0x00dbdbdb,
			0x00e0e0e0, 0x00323232, 0x003a3a3a, 0x000a0a0a, 0x00494949, 0x00060606, 0x00242424, 0x005c5c5c,
			0x00c2c2c2, 0x00d3d3d3, 0x00acacac, 0x00626262, 0x00919191, 0x00959595, 0x00e4e4e4, 0x00797979,
			0x00e7e7e7, 0x00c8c8c8, 0x00373737, 0x006d6d6d, 0x008d8d8d, 0x00d5d5d5, 0x004e4e4e, 0x00a9a9a9,
			0x006c6c6c, 0x00565656, 0x00f4f4f4, 0x00eaeaea, 0x00656565, 0x007a7a7a, 0x00aeaeae, 0x00080808,
			0x00bababa, 0x00787878, 0x00252525, 0x002e2e2e, 0x001c1c1c, 0x00a6a6a6, 0x00b4b4b4, 0x00c6c6c6,
			0x00e8e8e8, 0x00dddddd, 0x00747474, 0x001f1f1f, 0x004b4b4b, 0x00bdbdbd, 0x008b8b8b, 0x008a8a8a,
			0x00707070, 0x003e3e3e, 0x00b5b5b5, 0x00666666, 0x00484848, 0x00030303, 0x00f6f6f6, 0x000e0e0e,
			0x00616161, 0x00353535, 0x00575757, 0x00b9b9b9, 0x00868686, 0x00c1c1c1, 0x001d1d1d, 0x009e9e9e,
			0x00e1e1e1, 0x00f8f8f8, 0x00989898, 0x00111111, 0x00696969, 0x00d9d9d9, 0x008e8e8e, 0x00949494,
			0x009b9b9b, 0x001e1e1e, 0x00878787, 0x00e9e9e9, 0x00cecece, 0x00555555, 0x00282828, 0x00dfdfdf,
			0x008c8c8c, 0x00a1a1a1, 0x00898989, 0x000d0d0d, 0x00bfbfbf, 0x00e6e6e6, 0x00424242, 0x00686868,
			0x00414141, 0x00999999, 0x002d2d2d, 0x000f0f0f, 0x00b0b0b0, 0x00545454, 0x00bbbbbb, 0x00161616
		},
		{
			0xe200e2e2, 0x4e004e4e, 0x54005454, 0xfc00fcfc, 0x94009494, 0xc200c2c2, 0x4a004a4a, 0xcc00cccc,
			0x62006262, 0x0d000d0d, 0x6a006a6a, 0x46004646, 0x3c003c3c, 0x4d004d4d, 0x8b008b8b, 0xd100d1d1,
			0x5e005e5e, 0xfa00fafa, 0x64006464, 0xcb00cbcb, 0xb400b4b4, 0x97009797, 0xbe00bebe, 0x2b002b2b,
			0xbc00bcbc, 0x77007777, 0x2e002e2e, 0x03000303, 0xd300d3d3, 0x19001919, 0x59005959, 0xc100c1c1,
			0x1d001d1d, 0x06000606, 0x41004141, 0x6b006b6b, 0x55005555, 0xf000f0f0, 0x99009999, 0x69006969,
			0xea00eaea, 0x9c009c9c, 0x18001818, 0xae00aeae, 0x63006363, 0xdf00dfdf, 0xe700e7e7, 0xbb00bbbb,
			0x00000000, 0x73007373, 0x66006666, 0xfb00fbfb, 0x96009696, 0x4c004c4c, 0x85008585, 0xe400e4e4,
			0x3a003a3a, 0x09000909, 0x45004545, 0xaa00aaaa, 0x0f000f0f, 0xee00eeee, 0x10001010, 0xeb00ebeb,
			0x2d002d2d, 0x7f007f7f, 0xf400f4f4, 0x29002929, 0xac00acac, 0xcf00cfcf, 0xad00adad, 0x91009191,
			0x8d008d8d, 0x78007878, 0xc800c8c8, 0x95009595, 0xf900f9f9, 0x2f002f2f, 0xce00cece, 0xcd00cdcd,
			0x08000808, 0x7a007a7a, 0x88008888, 0x38003838, 0x5c005c5c, 0x83008383, 0x2a002a2a, 0x28002828,
			0x47004747, 0xdb00dbdb, 0xb800b8b8, 0xc700c7c7, 0x93009393, 0xa400a4a4, 0x12001212, 0x53005353,
			0xff00ffff, 0x87008787, 0x0e000e0e, 0x31003131, 0x36003636, 0x21002121, 0x58005858, 0x48004848,
			0x01000101, 0x8e008e8e, 0x37003737, 0x74007474, 0x32003232, 0xca00caca, 0xe900e9e9, 0xb100b1b1,
			0xb700b7b7, 0xab00abab, 0x0c000c0c, 0xd700d7d7, 0xc400c4c4, 0x56005656, 0x42004242, 0x26002626,
			0x07000707, 0x98009898, 0x60006060, 0xd900d9d9, 0xb600b6b6, 0xb900b9b9, 0x11001111, 0x40004040,
			0xec00ecec, 0x20002020, 0x8c008c8c, 0xbd00bdbd, 0xa000a0a0, 0xc900c9c9, 0x84008484, 0x04000404,
			0x49004949, 0x23002323, 0xf100f1f1, 0x4f004f4f, 0x50005050, 0x1f001f1f, 0x13001313, 0xdc00dcdc,
			0xd800d8d8, 0xc000c0c0, 0x9e009e9e, 0x57005757, 0xe300e3e3, 0xc300c3c3, 0x7b007b7b, 0x65006565,
			0x3b003b3b, 0x02000202, 0x8f008f8f, 0x3e003e3e, 0xe800e8e8, 0x25002525, 0x92009292, 0xe500e5e5,
			0x15001515, 0xdd00dddd, 0xfd00fdfd, 0x17001717, 0xa900a9a9, 0xbf00bfbf, 0xd400d4d4, 0x9a009a9a,
			0x7e007e7e, 0xc500c5c5, 0x39003939, 0x67006767, 0xfe00fefe, 0x76007676, 0x9d009d9d, 0x43004343,
			0xa700a7a7, 0xe100e1e1, 0xd000d0d0, 0xf500f5f5, 0x68006868, 0xf200f2f2, 0x1b001b1b, 0x34003434,
			0x70007070, 0x05000505, 0xa300a3a3, 0x8a008a8a, 0xd500d5d5, 0x79007979, 0x86008686, 0xa800a8a8,
			0x30003030, 0xc600c6c6, 0x51005151, 0x4b004b4b, 0x1e001e1e, 0xa600a6a6, 0x27002727, 0xf600f6f6,
			0x35003535, 0xd200d2d2, 0x6e006e6e, 0x24002424, 0x16001616, 0x82008282, 0x5f005f5f, 0xda00dada,
			0xe600e6e6, 0x75007575, 0xa200a2a2, 0xef00efef, 0x2c002c2c, 0xb200b2b2, 0x1c001c1c, 0x9f009f9f,
			0x5d005d5d, 0x6f006f6f, 0x80008080, 0x0a000a0a, 0x72007272, 0x44004444, 0x9b009b9b, 0x6c006c6c,
			0x90009090, 0x0b000b0b, 0x5b005b5b, 0x33003333, 0x7d007d7d, 0x5a005a5a, 0x52005252, 0xf300f3f3,
			0x61006161, 0xa100a1a1, 0xf700f7f7, 0xb000b0b0, 0xd600d6d6, 0x3f003f3f, 0x7c007c7c, 0x6d006d6d,
			0xed00eded, 0x14001414, 0xe000e0e0, 0xa500a5a5, 0x3d003d3d, 0x22002222, 0xb300b3b3, 0xf800f8f8,
			0x89008989, 0xde00dede, 0x71007171, 0x1a001a1a, 0xaf00afaf, 0xba00baba, 0xb500b5b5, 0x81008181
		},
		{
			0x52520052, 0x09090009, 0x6a6a006a, 0xd5d500d5, 0x30300030, 0x36360036, 0xa5a500a5, 0x38380038,
			0xbfbf00bf, 0x40400040, 0xa3a300a3, 0x9e9e009e, 0x81810081, 0xf3f300f3, 0xd7d700d7, 0xfbfb00fb,
			0x7c7c007c, 0xe3e300e3, 0x39390039, 0x82820082, 0x9b9b009b, 0x2f2f002f, 0xffff00ff, 0x87870087,
			0x34340034, 0x8e8e008e, 0x43430043, 0x44440044, 0xc4c400c4, 0xdede00de, 0xe9e900e9, 0xcbcb00cb,
			0x54540054, 0x7b7b007b, 0x94940094, 0x32320032, 0xa6a600a6, 0xc2c200c2, 0x23230023, 0x3d3d003d,
			0xeeee00ee, 0x4c4c004c, 0x95950095, 0x0b0b000b, 0x42420042, 0xfafa00fa, 0xc3c300c3, 0x4e4e004e,
			0x08080008, 0x2e2e002e, 0xa1a100a1, 0x66660066, 0x28280028, 0xd9d900d9, 0x24240024, 0xb2b200b2,
			0x76760076, 0x5b5b005b, 0xa2a200a2, 0x49490049, 0x6d6d006d, 0x8b8b008b, 0xd1d100d1, 0x25250025,
			0x72720072, 0xf8f800f8, 0xf6f600f6, 0x64640064, 0x86860086, 0x68680068, 0x98980098, 0x16160016,
			0xd4d400d4, 0xa4a400a4, 0x5c5c005c, 0xcccc00cc, 0x5d5d005d, 0x65650065, 0xb6b600b6, 0x92920092,
			0x6c6c006c, 0x70700070, 0x48480048, 0x50500050, 0xfdfd00fd, 0xeded00ed, 0xb9b900b9, 0xdada00da,
			0x5e5e005e, 0x15150015, 0x46460046, 0x57570057, 0xa7a700a7, 0x8d8d008d, 0x9d9d009d, 0x84840084,
			0x90900090, 0xd8d800d8, 0xabab00ab, 0x00000000, 0x8c8c008c, 0xbcbc00bc, 0xd3d300d3, 0x0a0a000a,
			0xf7f700f7, 0xe4e400e4, 0x58580058, 0x05050005, 0xb8b800b8, 0xb3b300b3, 0x45450045, 0x06060006,
			0xd0d000d0, 0x2c2c002c, 0x1e1e001e, 0x8f8f008f, 0xcaca00ca, 0x3f3f003f, 0x0f0f000f, 0x02020002,
			0xc1c100c1, 0xafaf00af, 0xbdbd00bd, 0x03030003, 0x01010001, 0x13130013, 0x8a8a008a, 0x6b6b006b,
			0x3a3a003a, 0x91910091, 0x11110011, 0x41410041, 0x4f4f004f, 0x67670067, 0xdcdc00dc, 0xeaea00ea,
			0x97970097, 0xf2f200f2, 0xcfcf00cf, 0xcece00ce, 0xf0f000f0, 0xb4b400b4, 0xe6e600e6, 0x73730073,
			0x96960096, 0xacac00ac, 0x74740074, 0x22220022, 0xe7e700e7, 0xadad00ad, 0x35350035, 0x85850085,
			0xe2e200e2, 0xf9f900f9, 0x37370037, 0xe8e800e8, 0x1c1c001c, 0x75750075, 0xdfdf00df, 0x6e6e006e,
			0x47470047, 0xf1f100f1, 0x1a1a001a, 0x71710071, 0x1d1d001d, 0x29290029, 0xc5c500c5, 0x89890089,
			0x6f6f006f, 0xb7b700b7, 0x62620062, 0x0e0e000e, 0xaaaa00aa, 0x18180018, 0xbebe00be, 0x1b1b001b,
			0xfcfc00fc, 0x56560056, 0x3e3e003e, 0x4b4b004b, 0xc6c600c6, 0xd2d200d2, 0x79790079, 0x20200020,
			0x9a9a009a, 0xdbdb00db, 0xc0c000c0, 0xfefe00fe, 0x78780078, 0xcdcd00cd, 0x5a5a005a, 0xf4f400f4,
			0x1f1f001f, 0xdddd00dd, 0xa8a800a8, 0x33330033, 0x88880088, 0x07070007, 0xc7c700c7, 0x31310031,
			0xb1b100b1, 0x12120012, 0x10100010, 0x59590059, 0x27270027, 0x80800080, 0xecec00ec, 0x5f5f005f,
			0x60600060, 0x51510051, 0x7f7f007f, 0xa9a900a9, 0x19190019, 0xb5b500b5, 0x4a4a004a, 0x0d0d000d,
			0x2d2d002d, 0xe5e500e5, 0x7a7a007a, 0x9f9f009f, 0x93930093, 0xc9c900c9, 0x9c9c009c, 0xefef00ef,
			0xa0a000a0, 0xe0e000e0, 0x3b3b003b, 0x4d4d004d, 0xaeae00ae, 0x2a2a002a, 0xf5f500f5, 0xb0b000b0,
			0xc8c800c8, 0xebeb00eb, 0xbbbb00bb, 0x3c3c003c, 0x83830083, 0x53530053, 0x99990099, 0x61610061,
			0x17170017, 0x2b2b002b, 0x04040004, 0x7e7e007e, 0xbaba00ba, 0x77770077, 0xd6d600d6, 0x26260026,
			0xe1e100e1, 0x69690069, 0x14140014, 0x63630063, 0x55550055, 0x21210021, 0x0c0c000c, 0x7d7d007d
		},
		{
			0x30303000, 0x68686800, 0x99999900, 0x1b1b1b00, 0x87878700, 0xb9b9b900, 0x21212100, 0x78787800,
			0x50505000, 0x39393900, 0xdbdbdb00, 0xe1e1e100, 0x72727200, 0x09090900, 0x62626200, 0x3c3c3c00,
			0x3e3e3e00, 0x7e7e7e00, 0x5e5e5e00, 0x8e8e8e00, 0xf1f1f100, 0xa0a0a000, 0xcccccc00, 0xa3a3a300,
			0x2a2a2a00, 0x1d1d1d00, 0xfbfbfb00, 0xb6b6b600, 0xd6d6d600, 0x20202000, 0xc4c4c400, 0x8d8d8d00,
			0x81818100, 0x65656500, 0xf5f5f500, 0x89898900, 0xcbcbcb00, 0x9d9d9d00, 0x77777700, 0xc6c6c600,
			0x57575700, 0x43434300, 0x56565600, 0x17171700, 0xd4d4d400, 0x40404000, 0x1a1a1a00, 0x4d4d4d00,
			0xc0c0c000, 0x63636300, 0x6c6c6c00, 0xe3e3e300, 0xb7b7b700, 0xc8c8c800, 0x64646400, 0x6a6a6a00,
			0x53535300, 0xaaaaaa00, 0x38383800, 0x98989800, 0x0c0c0c00, 0xf4f4f400, 0x9b9b9b00, 0xededed00,
			0x7f7f7f00, 0x22222200, 0x76767600, 0xafafaf00, 0xdddddd00, 0x3a3a3a00, 0x0b0b0b00, 0x58585800,
			0x67676700, 0x88888800, 0x06060600, 0xc3c3c300, 0x35353500, 0x0d0d0d00, 0x01010100, 0x8b8b8b00,
			0x8c8c8c00, 0xc2c2c200, 0xe6e6e600, 0x5f5f5f00, 0x02020200, 0x24242400, 0x75757500, 0x93939300,
			0x66666600, 0x1e1e1e00, 0xe5e5e500, 0xe2e2e200, 0x54545400, 0xd8d8d800, 0x10101000, 0xcecece00,
			0x7a7a7a00, 0xe8e8e800, 0x08080800, 0x2c2c2c00, 0x12121200, 0x97979700, 0x32323200, 0xababab00,
			0xb4b4b400, 0x27272700, 0x0a0a0a00, 0x23232300, 0xdfdfdf00, 0xefefef00, 0xcacaca00, 0xd9d9d900,
			0xb8b8b800, 0xfafafa00, 0xdcdcdc00, 0x31313100, 0x6b6b6b00, 0xd1d1d100, 0xadadad00, 0x19191900,
			0x49494900, 0xbdbdbd00, 0x51515100, 0x96969600, 0xeeeeee00, 0xe4e4e400, 0xa8a8a800, 0x41414100,
			0xdadada00, 0xffffff00, 0xcdcdcd00, 0x55555500, 0x86868600, 0x36363600, 0xbebebe00, 0x61616100,
			0x52525200, 0xf8f8f800, 0xbbbbbb00, 0x0e0e0e00, 0x82828200, 0x48484800, 0x69696900, 0x9a9a9a00,
			0xe0e0e000, 0x47474700, 0x9e9e9e00, 0x5c5c5c00, 0x04040400, 0x4b4b4b00, 0x34343400, 0x15151500,
			0x79797900, 0x26262600, 0xa7a7a700, 0xdedede00, 0x29292900, 0xaeaeae00, 0x92929200, 0xd7d7d700,
			0x84848400, 0xe9e9e900, 0xd2d2d200, 0xbababa00, 0x5d5d5d00, 0xf3f3f300, 0xc5c5c500, 0xb0b0b000,
			0xbfbfbf00, 0xa4a4a400, 0x3b3b3b00, 0x71717100, 0x44444400, 0x46464600, 0x2b2b2b00, 0xfcfcfc00,
			0xebebeb00, 0x6f6f6f00, 0xd5d5d500, 0xf6f6f600, 0x14141400, 0xfefefe00, 0x7c7c7c00, 0x70707000,
			0x5a5a5a00, 0x7d7d7d00, 0xfdfdfd00, 0x2f2f2f00, 0x18181800, 0x83838300, 0x16161600, 0xa5a5a500,
			0x91919100, 0x1f1f1f00, 0x05050500, 0x95959500, 0x74747400, 0xa9a9a900, 0xc1c1c100, 0x5b5b5b00,
			0x4a4a4a00, 0x85858500, 0x6d6d6d00, 0x13131300, 0x07070700, 0x4f4f4f00, 0x4e4e4e00, 0x45454500,
			0xb2b2b200, 0x0f0f0f00, 0xc9c9c900, 0x1c1c1c00, 0xa6a6a600, 0xbcbcbc00, 0xececec00, 0x73737300,
			0x90909000, 0x7b7b7b00, 0xcfcfcf00, 0x59595900, 0x8f8f8f00, 0xa1a1a100, 0xf9f9f900, 0x2d2d2d00,
			0xf2f2f200, 0xb1b1b100, 0x00000000, 0x94949400, 0x37373700, 0x9f9f9f00, 0xd0d0d000, 0x2e2e2e00,
			0x9c9c9c00, 0x6e6e6e00, 0x28282800, 0x3f3f3f00, 0x80808000, 0xf0f0f000, 0x3d3d3d00, 0xd3d3d300,
			0x25252500, 0x8a8a8a00, 0xb5b5b500, 0xe7e7e700, 0x42424200, 0xb3b3b300, 0xc7c7c700, 0xeaeaea00,
			0xf7f7f700, 0x4c4c4c00, 0x11111100, 0x33333300, 0x03030300, 0xa2a2a200, 0xacacac00, 0x60606000
		},
	};

	static const uint32_t C[3][4] = {
		{ 0x517cc1b7, 0x27220a94, /* 0xfe12abe8 ??? */ 0xfe13abe8, 0xfa9a6ee0 },
		{ 0x6db14acc, 0x9e21c820, 0xff28b1d5, 0xef5de2b0 },
		{ 0xdb92371d, 0x2126e970, 0x03249775, 0x04e8c90e }
	};

	static const unsigned char S[2][256] = {
		{
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
			0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
			0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
			0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
			0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
			0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
			0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
			0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
			0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
			0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
		},
		{
			0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
			0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
			0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
			0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
			0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
			0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
			0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
			0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
			0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
			0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
			0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
			0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
			0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
			0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
			0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
			0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81
		},
	};

	static const unsigned char IS[2][256] = {
		{
			0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
			0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
			0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
			0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
			0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
			0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
			0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
			0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
			0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
			0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
			0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
			0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
			0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
			0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
			0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
		},
		{
			0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c,
			0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d,
			0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d,
			0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed,
			0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b,
			0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce,
			0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9,
			0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41,
			0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a,
			0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7,
			0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc,
			0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5,
			0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45,
			0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d,
			0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3,
			0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60
		}
	};

	aria128::~aria128()
	{
		clear();
	}

	void aria128::clear()
	{
		zero_memory(rk, sizeof(rk));
	}

	static inline void IMC(uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3)
	{
		x0 = T[0][IS[0][(unsigned char)(x0 >> 24)]] ^ T[1][IS[1][(unsigned char)(x0 >> 16)]] ^ T[2][S[0][((unsigned char)(x0 >> 8))]] ^ T[3][S[1][((unsigned char)(x0))]];
		x1 = T[0][IS[0][(unsigned char)(x1 >> 24)]] ^ T[1][IS[1][(unsigned char)(x1 >> 16)]] ^ T[2][S[0][((unsigned char)(x1 >> 8))]] ^ T[3][S[1][((unsigned char)(x1))]];
		x2 = T[0][IS[0][(unsigned char)(x2 >> 24)]] ^ T[1][IS[1][(unsigned char)(x2 >> 16)]] ^ T[2][S[0][((unsigned char)(x2 >> 8))]] ^ T[3][S[1][((unsigned char)(x2))]];
		x3 = T[0][IS[0][(unsigned char)(x3 >> 24)]] ^ T[1][IS[1][(unsigned char)(x3 >> 16)]] ^ T[2][S[0][((unsigned char)(x3 >> 8))]] ^ T[3][S[1][((unsigned char)(x3))]];
		uint32_t t0 = x0 ^ x1 ^ x2;
		uint32_t t1 = x0 ^ x2 ^ x3;
		uint32_t t2 = x0 ^ x1 ^ x3;
		uint32_t t3 = x1 ^ x2 ^ x3;
		t1 = ((t1 << 8) & 0xff00ff00) | ((t1 >> 8) & 0x00ff00ff);
		t2 = rotater32(t2, 16);
		t3 = (t3 >> 24) | ((t3 >> 8) & 0x0000ff00) | ((t3 << 8) & 0x00ff0000) | (t3 << 24);
		x0 = t0 ^ t1 ^ t2;
		x1 = t0 ^ t2 ^ t3;
		x2 = t0 ^ t1 ^ t3;
		x3 = t1 ^ t2 ^ t3;
	}

	static inline void G(uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3, uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3)
	{
		x0 ^= k0;
		x1 ^= k1;
		x2 ^= k2;
		x3 ^= k3;

		x0 = T[0][(unsigned char)(x0 >> 24)] ^ T[1][(unsigned char)(x0 >> 16)] ^ T[2][((unsigned char)(x0 >> 8))] ^ T[3][((unsigned char)(x0))];
		x1 = T[0][(unsigned char)(x1 >> 24)] ^ T[1][(unsigned char)(x1 >> 16)] ^ T[2][((unsigned char)(x1 >> 8))] ^ T[3][((unsigned char)(x1))];
		x2 = T[0][(unsigned char)(x2 >> 24)] ^ T[1][(unsigned char)(x2 >> 16)] ^ T[2][((unsigned char)(x2 >> 8))] ^ T[3][((unsigned char)(x2))];
		x3 = T[0][(unsigned char)(x3 >> 24)] ^ T[1][(unsigned char)(x3 >> 16)] ^ T[2][((unsigned char)(x3 >> 8))] ^ T[3][((unsigned char)(x3))];
		uint32_t t0 = x0 ^ x1 ^ x2;
		uint32_t t1 = x0 ^ x2 ^ x3;
		uint32_t t2 = x0 ^ x1 ^ x3;
		uint32_t t3 = x1 ^ x2 ^ x3;
		t1 = ((t1 << 8) & 0xff00ff00) | ((t1 >> 8) & 0x00ff00ff);
		t2 = rotater32(t2, 16);
		t3 = (t3 >> 24) | ((t3 >> 8) & 0x0000ff00) | ((t3 << 8) & 0x00ff0000) | (t3 << 24);
		x0 = t0 ^ t1 ^ t2;
		x1 = t0 ^ t2 ^ t3;
		x2 = t0 ^ t1 ^ t3;
		x3 = t1 ^ t2 ^ t3;
	}

	static inline void IG(uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3, uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3)
	{
		x0 ^= k0;
		x1 ^= k1;
		x2 ^= k2;
		x3 ^= k3;
		x0 = T[2][(unsigned char)(x0 >> 24)] ^ T[3][(unsigned char)(x0 >> 16)] ^ T[0][((unsigned char)(x0 >> 8))] ^ T[1][((unsigned char)(x0))];
		x1 = T[2][(unsigned char)(x1 >> 24)] ^ T[3][(unsigned char)(x1 >> 16)] ^ T[0][((unsigned char)(x1 >> 8))] ^ T[1][((unsigned char)(x1))];
		x2 = T[2][(unsigned char)(x2 >> 24)] ^ T[3][(unsigned char)(x2 >> 16)] ^ T[0][((unsigned char)(x2 >> 8))] ^ T[1][((unsigned char)(x2))];
		x3 = T[2][(unsigned char)(x3 >> 24)] ^ T[3][(unsigned char)(x3 >> 16)] ^ T[0][((unsigned char)(x3 >> 8))] ^ T[1][((unsigned char)(x3))];
		uint32_t t0 = x0 ^ x1 ^ x2;
		uint32_t t1 = x0 ^ x2 ^ x3;
		uint32_t t2 = x0 ^ x1 ^ x3;
		uint32_t t3 = x1 ^ x2 ^ x3;
		t0 = rotater32(t0, 16);
		t1 = (t1 >> 24) | ((t1 >> 8) & 0x0000ff00) | ((t1 << 8) & 0x00ff0000) | (t1 << 24);
		t3 = ((t3 << 8) & 0xff00ff00) | ((t3 >> 8) & 0x00ff00ff);
		x0 = t0 ^ t1 ^ t2;
		x1 = t0 ^ t2 ^ t3;
		x2 = t0 ^ t1 ^ t3;
		x3 = t1 ^ t2 ^ t3;
	}

	static inline void LG(uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3, uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3)
	{
		x0 ^= k0;
		x1 ^= k1;
		x2 ^= k2;
		x3 ^= k3;
		x0 = (uint32_t(IS[0][(unsigned char)(x0 >> 24)]) << 24) ^ (uint32_t(IS[1][(unsigned char)(x0 >> 16)]) << 16) ^ (uint32_t(S[0][((unsigned char)(x0 >> 8))]) << 8) ^ uint32_t(S[1][((unsigned char)(x0))]);
		x1 = (uint32_t(IS[0][(unsigned char)(x1 >> 24)]) << 24) ^ (uint32_t(IS[1][(unsigned char)(x1 >> 16)]) << 16) ^ (uint32_t(S[0][((unsigned char)(x1 >> 8))]) << 8) ^ uint32_t(S[1][((unsigned char)(x1))]);
		x2 = (uint32_t(IS[0][(unsigned char)(x2 >> 24)]) << 24) ^ (uint32_t(IS[1][(unsigned char)(x2 >> 16)]) << 16) ^ (uint32_t(S[0][((unsigned char)(x2 >> 8))]) << 8) ^ uint32_t(S[1][((unsigned char)(x2))]);
		x3 = (uint32_t(IS[0][(unsigned char)(x3 >> 24)]) << 24) ^ (uint32_t(IS[1][(unsigned char)(x3 >> 16)]) << 16) ^ (uint32_t(S[0][((unsigned char)(x3 >> 8))]) << 8) ^ uint32_t(S[1][((unsigned char)(x3))]);
	}

	static inline void genrk19r(uint32_t x1, uint32_t x2, uint32_t x3, uint32_t x4, uint32_t y1, uint32_t y2, uint32_t y3, uint32_t y4, uint32_t& rk1, uint32_t& rk2, uint32_t& rk3, uint32_t& rk4)
	{
		rk1 = (x4 << 13) ^ (x1 >> 19) ^ y1;
		rk2 = (x1 << 13) ^ (x2 >> 19) ^ y2;
		rk3 = (x2 << 13) ^ (x3 >> 19) ^ y3;
		rk4 = (x3 << 13) ^ (x4 >> 19) ^ y4;
	}

	static inline void genrk31r(uint32_t x1, uint32_t x2, uint32_t x3, uint32_t x4, uint32_t y1, uint32_t y2, uint32_t y3, uint32_t y4, uint32_t& rk1, uint32_t& rk2, uint32_t& rk3, uint32_t& rk4)
	{
		rk1 = (x4 << 1) ^ (x1 >> 31) ^ y1;
		rk2 = (x1 << 1) ^ (x2 >> 31) ^ y2;
		rk3 = (x2 << 1) ^ (x3 >> 31) ^ y3;
		rk4 = (x3 << 1) ^ (x4 >> 31) ^ y4;
	}

	static inline void genrk19l(uint32_t x1, uint32_t x2, uint32_t x3, uint32_t x4, uint32_t y1, uint32_t y2, uint32_t y3, uint32_t y4, uint32_t& rk1, uint32_t& rk2, uint32_t& rk3, uint32_t& rk4)
	{
		rk1 = (x2 >> 13) ^ (x1 << 19) ^ y1;
		rk2 = (x3 >> 13) ^ (x2 << 19) ^ y2;
		rk3 = (x4 >> 13) ^ (x3 << 19) ^ y3;
		rk4 = (x1 >> 13) ^ (x4 << 19) ^ y4;
	}

	static inline void genrk31l(uint32_t x1, uint32_t x2, uint32_t x3, uint32_t x4, uint32_t y1, uint32_t y2, uint32_t y3, uint32_t y4, uint32_t& rk1, uint32_t& rk2, uint32_t& rk3, uint32_t& rk4)
	{
		rk1 = (x2 >> 1) ^ (x1 << 31) ^ y1;
		rk2 = (x3 >> 1) ^ (x2 << 31) ^ y2;
		rk3 = (x4 >> 1) ^ (x3 << 31) ^ y3;
		rk4 = (x1 >> 1) ^ (x4 << 31) ^ y4;
	}

	static inline void genrk61l(uint32_t x1, uint32_t x2, uint32_t x3, uint32_t x4, uint32_t y1, uint32_t y2, uint32_t y3, uint32_t y4, uint32_t& rk1, uint32_t& rk2, uint32_t& rk3, uint32_t& rk4)
	{
		rk1 = (x3 >> 3) ^ (x2 << 29) ^ y1;
		rk2 = (x4 >> 3) ^ (x3 << 29) ^ y2;
		rk3 = (x1 >> 3) ^ (x4 << 29) ^ y3;
		rk4 = (x2 >> 3) ^ (x1 << 29) ^ y4;
	}

	static inline void keyswap(uint32_t* w, int Nr)
	{
		for (int i = 0; i < 4 * Nr / 2; i += 4)
		{
			std::swap(w[i + 0], w[4 * Nr + 0 - i]);
			std::swap(w[i + 1], w[4 * Nr + 1 - i]);
			std::swap(w[i + 2], w[4 * Nr + 2 - i]);
			std::swap(w[i + 3], w[4 * Nr + 3 - i]);
		}
	}


	bool aria128::init(const unsigned char* key, block_cipher::direction direction)
	{
		uint32_t W00 = swap_uint32(*(((const uint32_t*)key) + 0));
		uint32_t W01 = swap_uint32(*(((const uint32_t*)key) + 1));
		uint32_t W02 = swap_uint32(*(((const uint32_t*)key) + 2));
		uint32_t W03 = swap_uint32(*(((const uint32_t*)key) + 3));
		uint32_t W10 = W00;
		uint32_t W11 = W01;
		uint32_t W12 = W02;
		uint32_t W13 = W03;
		G(W10, W11, W12, W13, C[0][0], C[0][1], C[0][2], C[0][3]);
		uint32_t W20 = W10;
		uint32_t W21 = W11;
		uint32_t W22 = W12;
		uint32_t W23 = W13;
		IG(W20, W21, W22, W23, C[1][0], C[1][1], C[1][2], C[1][3]);
		W20 ^= W00;
		W21 ^= W01;
		W22 ^= W02;
		W23 ^= W03;
		uint32_t W30 = W20;
		uint32_t W31 = W21;
		uint32_t W32 = W22;
		uint32_t W33 = W23;
		G(W30, W31, W32, W33, C[2][0], C[2][1], C[2][2], C[2][3]);
		W30 ^= W10;
		W31 ^= W11;
		W32 ^= W12;
		W33 ^= W13;

#ifdef CPPCRYPTO_DEBUG
		printf("W0: %08x %08x %08x %08x\n", W00, W01, W02, W03);
		printf("W1: %08x %08x %08x %08x\n", W10, W11, W12, W13);
		printf("W2: %08x %08x %08x %08x\n", W20, W21, W22, W23);
		printf("W3: %08x %08x %08x %08x\n", W30, W31, W32, W33);
#endif

		genrk19r(W10, W11, W12, W13, W00, W01, W02, W03, rk[0], rk[1], rk[2], rk[3]);
		genrk19r(W20, W21, W22, W23, W10, W11, W12, W13, rk[4], rk[5], rk[6], rk[7]);
		genrk19r(W30, W31, W32, W33, W20, W21, W22, W23, rk[8], rk[9], rk[10], rk[11]);
		genrk19r(W00, W01, W02, W03, W30, W31, W32, W33, rk[12], rk[13], rk[14], rk[15]);
		genrk31r(W10, W11, W12, W13, W00, W01, W02, W03, rk[16], rk[17], rk[18], rk[19]);
		genrk31r(W20, W21, W22, W23, W10, W11, W12, W13, rk[20], rk[21], rk[22], rk[23]);
		genrk31r(W30, W31, W32, W33, W20, W21, W22, W23, rk[24], rk[25], rk[26], rk[27]);
		genrk31r(W00, W01, W02, W03, W30, W31, W32, W33, rk[28], rk[29], rk[30], rk[31]);
		genrk61l(W10, W11, W12, W13, W00, W01, W02, W03, rk[32], rk[33], rk[34], rk[35]);
		genrk61l(W20, W21, W22, W23, W10, W11, W12, W13, rk[36], rk[37], rk[38], rk[39]);
		genrk61l(W30, W31, W32, W33, W20, W21, W22, W23, rk[40], rk[41], rk[42], rk[43]);
		genrk61l(W00, W01, W02, W03, W30, W31, W32, W33, rk[44], rk[45], rk[46], rk[47]);
		genrk31l(W10, W11, W12, W13, W00, W01, W02, W03, rk[48], rk[49], rk[50], rk[51]);

		if (direction == decryption)
		{
			keyswap(rk, 12);
			IMC(rk[4], rk[5], rk[6], rk[7]);
			IMC(rk[8], rk[9], rk[10], rk[11]);
			IMC(rk[12], rk[13], rk[14], rk[15]);
			IMC(rk[16], rk[17], rk[18], rk[19]);
			IMC(rk[20], rk[21], rk[22], rk[23]);
			IMC(rk[24], rk[25], rk[26], rk[27]);
			IMC(rk[28], rk[29], rk[30], rk[31]);
			IMC(rk[32], rk[33], rk[34], rk[35]);
			IMC(rk[36], rk[37], rk[38], rk[39]);
			IMC(rk[40], rk[41], rk[42], rk[43]);
			IMC(rk[44], rk[45], rk[46], rk[47]);
		}

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 52; i += 4)
			printf("RK[%d]: %08x %08x %08x %08x\n", i, rk[i], rk[i + 1], rk[i + 2], rk[i + 3]);
#endif

		return true;
	}

	void aria128::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint32_t x0 = swap_uint32(*(((const uint32_t*)in) + 0));
		uint32_t x1 = swap_uint32(*(((const uint32_t*)in) + 1));
		uint32_t x2 = swap_uint32(*(((const uint32_t*)in) + 2));
		uint32_t x3 = swap_uint32(*(((const uint32_t*)in) + 3));

		G(x0, x1, x2, x3, rk[0], rk[1], rk[2], rk[3]); // round 1
		IG(x0, x1, x2, x3, rk[4], rk[5], rk[6], rk[7]); // round 2
		G(x0, x1, x2, x3, rk[8], rk[9], rk[10], rk[11]); // round 3
		IG(x0, x1, x2, x3, rk[12], rk[13], rk[14], rk[15]); // round 4
		G(x0, x1, x2, x3, rk[16], rk[17], rk[18], rk[19]); // round 5
		IG(x0, x1, x2, x3, rk[20], rk[21], rk[22], rk[23]); // round 6
		G(x0, x1, x2, x3, rk[24], rk[25], rk[26], rk[27]); // round 7
		IG(x0, x1, x2, x3, rk[28], rk[29], rk[30], rk[31]); // round 8
		G(x0, x1, x2, x3, rk[32], rk[33], rk[34], rk[35]); // round 9
		IG(x0, x1, x2, x3, rk[36], rk[37], rk[38], rk[39]); // round 10
		G(x0, x1, x2, x3, rk[40], rk[41], rk[42], rk[43]); // round 11
		LG(x0, x1, x2, x3, rk[44], rk[45], rk[46], rk[47]); // round 12

		*(((uint32_t*)out) + 0) = swap_uint32(x0 ^ rk[48]);
		*(((uint32_t*)out) + 1) = swap_uint32(x1 ^ rk[49]);
		*(((uint32_t*)out) + 2) = swap_uint32(x2 ^ rk[50]);
		*(((uint32_t*)out) + 3) = swap_uint32(x3 ^ rk[51]);
	}

	void aria128::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		encrypt_block(in, out);
	}

	void aria256::clear()
	{
		zero_memory(rk, sizeof(rk));
	}

	aria256::~aria256()
	{
		clear();
	}

	void aria256::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint32_t x0 = swap_uint32(*(((const uint32_t*)in) + 0));
		uint32_t x1 = swap_uint32(*(((const uint32_t*)in) + 1));
		uint32_t x2 = swap_uint32(*(((const uint32_t*)in) + 2));
		uint32_t x3 = swap_uint32(*(((const uint32_t*)in) + 3));

		G(x0, x1, x2, x3, rk[0], rk[1], rk[2], rk[3]); // round 1
		IG(x0, x1, x2, x3, rk[4], rk[5], rk[6], rk[7]); // round 2
		G(x0, x1, x2, x3, rk[8], rk[9], rk[10], rk[11]); // round 3
		IG(x0, x1, x2, x3, rk[12], rk[13], rk[14], rk[15]); // round 4
		G(x0, x1, x2, x3, rk[16], rk[17], rk[18], rk[19]); // round 5
		IG(x0, x1, x2, x3, rk[20], rk[21], rk[22], rk[23]); // round 6
		G(x0, x1, x2, x3, rk[24], rk[25], rk[26], rk[27]); // round 7
		IG(x0, x1, x2, x3, rk[28], rk[29], rk[30], rk[31]); // round 8
		G(x0, x1, x2, x3, rk[32], rk[33], rk[34], rk[35]); // round 9
		IG(x0, x1, x2, x3, rk[36], rk[37], rk[38], rk[39]); // round 10
		G(x0, x1, x2, x3, rk[40], rk[41], rk[42], rk[43]); // round 11
		IG(x0, x1, x2, x3, rk[44], rk[45], rk[46], rk[47]); // round 12
		G(x0, x1, x2, x3, rk[48], rk[49], rk[50], rk[51]); // round 13
		IG(x0, x1, x2, x3, rk[52], rk[53], rk[54], rk[55]); // round 14
		G(x0, x1, x2, x3, rk[56], rk[57], rk[58], rk[59]); // round 15
		LG(x0, x1, x2, x3, rk[60], rk[61], rk[62], rk[63]); // round 16

		*(((uint32_t*)out) + 0) = swap_uint32(x0 ^ rk[64]);
		*(((uint32_t*)out) + 1) = swap_uint32(x1 ^ rk[65]);
		*(((uint32_t*)out) + 2) = swap_uint32(x2 ^ rk[66]);
		*(((uint32_t*)out) + 3) = swap_uint32(x3 ^ rk[67]);
	}

	void aria256::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		encrypt_block(in, out);
	}


	bool aria256::init(const unsigned char* key, block_cipher::direction direction)
	{
		uint32_t W00 = swap_uint32(*(((const uint32_t*)key) + 0));
		uint32_t W01 = swap_uint32(*(((const uint32_t*)key) + 1));
		uint32_t W02 = swap_uint32(*(((const uint32_t*)key) + 2));
		uint32_t W03 = swap_uint32(*(((const uint32_t*)key) + 3));
		uint32_t W10 = W00;
		uint32_t W11 = W01;
		uint32_t W12 = W02;
		uint32_t W13 = W03;
		G(W10, W11, W12, W13, C[2][0], C[2][1], C[2][2], C[2][3]);
		W10 ^= swap_uint32(*(((const uint32_t*)key) + 4));
		W11 ^= swap_uint32(*(((const uint32_t*)key) + 5));
		W12 ^= swap_uint32(*(((const uint32_t*)key) + 6));
		W13 ^= swap_uint32(*(((const uint32_t*)key) + 7));
		uint32_t W20 = W10;
		uint32_t W21 = W11;
		uint32_t W22 = W12;
		uint32_t W23 = W13;
		IG(W20, W21, W22, W23, C[0][0], C[0][1], C[0][2], C[0][3]);
		W20 ^= W00;
		W21 ^= W01;
		W22 ^= W02;
		W23 ^= W03;
		uint32_t W30 = W20;
		uint32_t W31 = W21;
		uint32_t W32 = W22;
		uint32_t W33 = W23;
		G(W30, W31, W32, W33, C[1][0], C[1][1], C[1][2], C[1][3]);
		W30 ^= W10;
		W31 ^= W11;
		W32 ^= W12;
		W33 ^= W13;

#ifdef CPPCRYPTO_DEBUG
		printf("W0: %08x %08x %08x %08x\n", W00, W01, W02, W03);
		printf("W1: %08x %08x %08x %08x\n", W10, W11, W12, W13);
		printf("W2: %08x %08x %08x %08x\n", W20, W21, W22, W23);
		printf("W3: %08x %08x %08x %08x\n", W30, W31, W32, W33);
#endif

		genrk19r(W10, W11, W12, W13, W00, W01, W02, W03, rk[0], rk[1], rk[2], rk[3]);
		genrk19r(W20, W21, W22, W23, W10, W11, W12, W13, rk[4], rk[5], rk[6], rk[7]);
		genrk19r(W30, W31, W32, W33, W20, W21, W22, W23, rk[8], rk[9], rk[10], rk[11]);
		genrk19r(W00, W01, W02, W03, W30, W31, W32, W33, rk[12], rk[13], rk[14], rk[15]);
		genrk31r(W10, W11, W12, W13, W00, W01, W02, W03, rk[16], rk[17], rk[18], rk[19]);
		genrk31r(W20, W21, W22, W23, W10, W11, W12, W13, rk[20], rk[21], rk[22], rk[23]);
		genrk31r(W30, W31, W32, W33, W20, W21, W22, W23, rk[24], rk[25], rk[26], rk[27]);
		genrk31r(W00, W01, W02, W03, W30, W31, W32, W33, rk[28], rk[29], rk[30], rk[31]);
		genrk61l(W10, W11, W12, W13, W00, W01, W02, W03, rk[32], rk[33], rk[34], rk[35]);
		genrk61l(W20, W21, W22, W23, W10, W11, W12, W13, rk[36], rk[37], rk[38], rk[39]);
		genrk61l(W30, W31, W32, W33, W20, W21, W22, W23, rk[40], rk[41], rk[42], rk[43]);
		genrk61l(W00, W01, W02, W03, W30, W31, W32, W33, rk[44], rk[45], rk[46], rk[47]);
		genrk31l(W10, W11, W12, W13, W00, W01, W02, W03, rk[48], rk[49], rk[50], rk[51]);
		genrk31l(W20, W21, W22, W23, W10, W11, W12, W13, rk[52], rk[53], rk[54], rk[55]);
		genrk31l(W30, W31, W32, W33, W20, W21, W22, W23, rk[56], rk[57], rk[58], rk[59]);
		genrk31l(W00, W01, W02, W03, W30, W31, W32, W33, rk[60], rk[61], rk[62], rk[63]);
		genrk19l(W10, W11, W12, W13, W00, W01, W02, W03, rk[64], rk[65], rk[66], rk[67]);

		if (direction == decryption)
		{
			keyswap(rk, 16);
			IMC(rk[4], rk[5], rk[6], rk[7]);
			IMC(rk[8], rk[9], rk[10], rk[11]);
			IMC(rk[12], rk[13], rk[14], rk[15]);
			IMC(rk[16], rk[17], rk[18], rk[19]);
			IMC(rk[20], rk[21], rk[22], rk[23]);
			IMC(rk[24], rk[25], rk[26], rk[27]);
			IMC(rk[28], rk[29], rk[30], rk[31]);
			IMC(rk[32], rk[33], rk[34], rk[35]);
			IMC(rk[36], rk[37], rk[38], rk[39]);
			IMC(rk[40], rk[41], rk[42], rk[43]);
			IMC(rk[44], rk[45], rk[46], rk[47]);
			IMC(rk[48], rk[49], rk[50], rk[51]);
			IMC(rk[52], rk[53], rk[54], rk[55]);
			IMC(rk[56], rk[57], rk[58], rk[59]);
			IMC(rk[60], rk[61], rk[62], rk[63]);
		}

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 68; i += 4)
			printf("RK[%d]: %08x %08x %08x %08x\n", i, rk[i], rk[i + 1], rk[i + 2], rk[i + 3]);
#endif

		return true;
	}

	aria192::~aria192()
	{
		clear();
	}

	void aria192::clear()
	{
		zero_memory(rk, sizeof(rk));
	}


	void aria192::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint32_t x0 = swap_uint32(*(((const uint32_t*)in) + 0));
		uint32_t x1 = swap_uint32(*(((const uint32_t*)in) + 1));
		uint32_t x2 = swap_uint32(*(((const uint32_t*)in) + 2));
		uint32_t x3 = swap_uint32(*(((const uint32_t*)in) + 3));

		G(x0, x1, x2, x3, rk[0], rk[1], rk[2], rk[3]); // round 1
		IG(x0, x1, x2, x3, rk[4], rk[5], rk[6], rk[7]); // round 2
		G(x0, x1, x2, x3, rk[8], rk[9], rk[10], rk[11]); // round 3
		IG(x0, x1, x2, x3, rk[12], rk[13], rk[14], rk[15]); // round 4
		G(x0, x1, x2, x3, rk[16], rk[17], rk[18], rk[19]); // round 5
		IG(x0, x1, x2, x3, rk[20], rk[21], rk[22], rk[23]); // round 6
		G(x0, x1, x2, x3, rk[24], rk[25], rk[26], rk[27]); // round 7
		IG(x0, x1, x2, x3, rk[28], rk[29], rk[30], rk[31]); // round 8
		G(x0, x1, x2, x3, rk[32], rk[33], rk[34], rk[35]); // round 9
		IG(x0, x1, x2, x3, rk[36], rk[37], rk[38], rk[39]); // round 10
		G(x0, x1, x2, x3, rk[40], rk[41], rk[42], rk[43]); // round 11
		IG(x0, x1, x2, x3, rk[44], rk[45], rk[46], rk[47]); // round 12
		G(x0, x1, x2, x3, rk[48], rk[49], rk[50], rk[51]); // round 13
		LG(x0, x1, x2, x3, rk[52], rk[53], rk[54], rk[55]); // round 14

		*(((uint32_t*)out) + 0) = swap_uint32(x0 ^ rk[56]);
		*(((uint32_t*)out) + 1) = swap_uint32(x1 ^ rk[57]);
		*(((uint32_t*)out) + 2) = swap_uint32(x2 ^ rk[58]);
		*(((uint32_t*)out) + 3) = swap_uint32(x3 ^ rk[59]);
	}

	void aria192::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		encrypt_block(in, out);
	}


	bool aria192::init(const unsigned char* key, block_cipher::direction direction)
	{
		uint32_t W00 = swap_uint32(*(((const uint32_t*)key) + 0));
		uint32_t W01 = swap_uint32(*(((const uint32_t*)key) + 1));
		uint32_t W02 = swap_uint32(*(((const uint32_t*)key) + 2));
		uint32_t W03 = swap_uint32(*(((const uint32_t*)key) + 3));
		uint32_t W10 = W00;
		uint32_t W11 = W01;
		uint32_t W12 = W02;
		uint32_t W13 = W03;
		G(W10, W11, W12, W13, C[1][0], C[1][1], C[1][2], C[1][3]);
		W10 ^= swap_uint32(*(((const uint32_t*)key) + 4));
		W11 ^= swap_uint32(*(((const uint32_t*)key) + 5));
		uint32_t W20 = W10;
		uint32_t W21 = W11;
		uint32_t W22 = W12;
		uint32_t W23 = W13;
		IG(W20, W21, W22, W23, C[2][0], C[2][1], C[2][2], C[2][3]);
		W20 ^= W00;
		W21 ^= W01;
		W22 ^= W02;
		W23 ^= W03;
		uint32_t W30 = W20;
		uint32_t W31 = W21;
		uint32_t W32 = W22;
		uint32_t W33 = W23;
		G(W30, W31, W32, W33, C[0][0], C[0][1], C[0][2], C[0][3]);
		W30 ^= W10;
		W31 ^= W11;
		W32 ^= W12;
		W33 ^= W13;

#ifdef CPPCRYPTO_DEBUG
		printf("W0: %08x %08x %08x %08x\n", W00, W01, W02, W03);
		printf("W1: %08x %08x %08x %08x\n", W10, W11, W12, W13);
		printf("W2: %08x %08x %08x %08x\n", W20, W21, W22, W23);
		printf("W3: %08x %08x %08x %08x\n", W30, W31, W32, W33);
#endif

		genrk19r(W10, W11, W12, W13, W00, W01, W02, W03, rk[0], rk[1], rk[2], rk[3]);
		genrk19r(W20, W21, W22, W23, W10, W11, W12, W13, rk[4], rk[5], rk[6], rk[7]);
		genrk19r(W30, W31, W32, W33, W20, W21, W22, W23, rk[8], rk[9], rk[10], rk[11]);
		genrk19r(W00, W01, W02, W03, W30, W31, W32, W33, rk[12], rk[13], rk[14], rk[15]);
		genrk31r(W10, W11, W12, W13, W00, W01, W02, W03, rk[16], rk[17], rk[18], rk[19]);
		genrk31r(W20, W21, W22, W23, W10, W11, W12, W13, rk[20], rk[21], rk[22], rk[23]);
		genrk31r(W30, W31, W32, W33, W20, W21, W22, W23, rk[24], rk[25], rk[26], rk[27]);
		genrk31r(W00, W01, W02, W03, W30, W31, W32, W33, rk[28], rk[29], rk[30], rk[31]);
		genrk61l(W10, W11, W12, W13, W00, W01, W02, W03, rk[32], rk[33], rk[34], rk[35]);
		genrk61l(W20, W21, W22, W23, W10, W11, W12, W13, rk[36], rk[37], rk[38], rk[39]);
		genrk61l(W30, W31, W32, W33, W20, W21, W22, W23, rk[40], rk[41], rk[42], rk[43]);
		genrk61l(W00, W01, W02, W03, W30, W31, W32, W33, rk[44], rk[45], rk[46], rk[47]);
		genrk31l(W10, W11, W12, W13, W00, W01, W02, W03, rk[48], rk[49], rk[50], rk[51]);
		genrk31l(W20, W21, W22, W23, W10, W11, W12, W13, rk[52], rk[53], rk[54], rk[55]);
		genrk31l(W30, W31, W32, W33, W20, W21, W22, W23, rk[56], rk[57], rk[58], rk[59]);

		if (direction == decryption)
		{
			keyswap(rk, 14);
			IMC(rk[4], rk[5], rk[6], rk[7]);
			IMC(rk[8], rk[9], rk[10], rk[11]);
			IMC(rk[12], rk[13], rk[14], rk[15]);
			IMC(rk[16], rk[17], rk[18], rk[19]);
			IMC(rk[20], rk[21], rk[22], rk[23]);
			IMC(rk[24], rk[25], rk[26], rk[27]);
			IMC(rk[28], rk[29], rk[30], rk[31]);
			IMC(rk[32], rk[33], rk[34], rk[35]);
			IMC(rk[36], rk[37], rk[38], rk[39]);
			IMC(rk[40], rk[41], rk[42], rk[43]);
			IMC(rk[44], rk[45], rk[46], rk[47]);
			IMC(rk[48], rk[49], rk[50], rk[51]);
			IMC(rk[52], rk[53], rk[54], rk[55]);
		}

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 60; i += 4)
			printf("RK[%d]: %08x %08x %08x %08x\n", i, rk[i], rk[i + 1], rk[i + 2], rk[i + 3]);
#endif

		return true;
	}

#if 0
	void gen_tables()
	{
		printf("static const uint32_t T[4][256] = {\n\t{\n\t\t");
		for (int i = 0; i < 256; i++)
		{
			printf("0x%02x%02x%02x%02x", 0, S[0][i], S[0][i], S[0][i]);
			if (i == 255)
				printf("\n\t},\n\t{\n\t\t");
			else if (i % 8 == 7)
				printf(",\n\t\t");
			else
				printf(", ");
		}
		for (int i = 0; i < 256; i++)
		{
			printf("0x%02x%02x%02x%02x", S[1][i], 0, S[1][i], S[1][i]);
			if (i == 255)
				printf("\n\t},\n\t{\n\t\t");
			else if (i % 8 == 7)
				printf(",\n\t\t");
			else
				printf(", ");
		}
		for (int i = 0; i < 256; i++)
		{
			printf("0x%02x%02x%02x%02x", IS[0][i], IS[0][i], 0, IS[0][i]);
			if (i == 255)
				printf("\n\t},\n\t{\n\t\t");
			else if (i % 8 == 7)
				printf(",\n\t\t");
			else
				printf(", ");
		}
		for (int i = 0; i < 256; i++)
		{
			printf("0x%02x%02x%02x%02x", IS[1][i], IS[1][i], IS[1][i], 0);
			if (i == 255)
				printf("\n\t},\n};\n");
			else if (i % 8 == 7)
				printf(",\n\t\t");
			else
				printf(", ");
		}

	}
#endif
}
