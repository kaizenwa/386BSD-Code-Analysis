/**************************************************************************
**
**  $Id: ncr_reg.h,v 2.0.0.3 94/07/24 08:59:19 wolf Exp $
**
**  #define   the NCR 53 C 810 Register Structure
**  #define   the NCR 53 C 810 Scripts Language
**
**-------------------------------------------------------------------------
**
**  Copyright (c) 1994  Wolfgang Stanglmeier, Koeln, Germany
**	                <wolf@dentaro.GUN.de>
**
**  This is a beta version - use with care.
**
**-------------------------------------------------------------------------
**
**  $Log:	ncr_reg.h,v $
**  Revision 2.0.0.3  94/07/24  08:59:19  wolf
**  bits of sstat0 defined.
**  
**  Revision 2.0  94/07/10  15:53:27  wolf
**  FreeBSD release.
**  
**  Revision 1.0  94/06/07  20:02:21  wolf
**  Beta release.
**
***************************************************************************
*/

#ifndef __NCR_REG_H__
#define __NCR_REG_H__


/*-----------------------------------------------------------------
**
**	The ncr 53c810 register structure.
**
**-----------------------------------------------------------------
*/

struct ncr_reg {
/*00*/  u_char    nc_scntl0;    /* full arb., ena parity, par->ATN  */
/*01*/  u_char    nc_scntl1;    /* no reset                         */
        #define   ISCON   0x10  /* connected to scsi		    */
        #define   CRST    0x08  /* force reset                      */
/*02*/  u_char    nc_scntl2;    /* no disconnect expected           */
/*03*/  u_char    nc_scntl3;    /* cnf system clock dependent       */
/*04*/  u_char    nc_scid;      /* cnf host adapter scsi address    */
	#define   RRE     0x40  /* r/w:e enable response to resel.  */
	#define   SRE     0x20  /* r/w:e enable response to select  */
/*05*/  u_char    nc_sxfer;     /* ### Sync speed and count         */
/*06*/  u_char    nc_sdid;      /* ### Destination-ID               */
/*07*/  u_char    nc_gpreg;     /* ??? IO-Pins                      */
/*08*/  u_char    nc_sfbr;      /* ### First byte in phase          */
/*09*/  u_char    nc_socl;
	#define   CREQ	  0x80	/* r/w: SCSI-REQ                    */
	#define   CACK	  0x40	/* r/w: SCSI-ACK                    */
	#define   CBSY	  0x20	/* r/w: SCSI-BSY                    */
	#define   CSEL	  0x10	/* r/w: SCSI-SEL                    */
	#define   CATN	  0x08	/* r/w: SCSI-ATN                    */
	#define   CMSG	  0x04	/* r/w: SCSI-MSG                    */
	#define   CC_D	  0x02	/* r/w: SCSI-C_D                    */
	#define   CI_O	  0x01	/* r/w: SCSI-I_O                    */
/*0a*/  u_char    nc_ssid;
/*0b*/  u_char    nc_sbcl;
/*0c*/  u_char    nc_dstat;
        #define   DFE     0x80  /* sta: dma fifo empty              */
        #define   MDPE    0x40  /* int: master data parity error    */
        #define   BF      0x20  /* int: script: bus fault           */
        #define   ABRT    0x10  /* int: script: command aborted     */
        #define   SSI     0x08  /* int: script: single step         */
        #define   SIR     0x04  /* int: script: interrupt instruct. */
        #define   IID     0x01  /* int: script: illegal instruct.   */
/*0d*/  u_char    nc_sstat0;
        #define   ILF     0x80  /* sta: data in SIDL register       */
        #define   ORF     0x40  /* sta: data in SODR register       */
        #define   OLF     0x20  /* sta: data in SODL register       */
        #define   AIP     0x10  /* sta: arbitration in progress     */
        #define   LOA     0x08  /* sta: arbitration lost            */
        #define   WOA     0x04  /* sta: arbitration won             */
        #define   IRST    0x02  /* sta: scsi reset signal           */
        #define   SDP     0x01  /* sta: scsi parity signal          */
/*0e*/  u_char    nc_sstat1;
/*0f*/  u_char    nc_sstat2;

/*10*/  u_long    nc_dsa;       /* --> Base page                    */
/*14*/  u_char    nc_istat;     /* --> Main Command and status      */
        #define   CABRT   0x80  /* cmd: abort current operation     */
        #define   SRST    0x40  /* mod: reset chip                  */
        #define   SIGP    0x20  /* r/w: message from host to ncr    */
        #define   SEM     0x10  /* r/w: message between host + ncr  */
        #define   CON     0x08  /* sta: connected to scsi           */
        #define   INTF    0x04  /* sta: int on the fly (reset by wr)*/
        #define   SIP     0x02  /* sta: scsi-interupt               */
        #define   DIP     0x01  /* sta: host/script interupt        */
/*15*/  u_char    nc_15_;
/*16*/	u_char	  nc_16_;
/*17*/  u_char    nc_17_;
/*18*/	u_char	  nc_ctest0;
/*19*/  u_char    nc_ctest1;
/*1a*/  u_char    nc_ctest2;
	#define   CSIGP   0x40
/*1b*/  u_char    nc_ctest3;
	#define   CLF	  0x04	/* clear scsi fifo		    */
/*1c*/  u_long    nc_temp;      /* ### Temporary stack              */
/*20*/	u_char	  nc_dfifo;
/*21*/  u_char    nc_ctest4;
/*22*/  u_char    nc_ctest5;
/*23*/  u_char    nc_ctest6;
/*24*/  u_long    nc_dbc;       /* ### Byte count and command       */
/*28*/  u_long    nc_dnad;      /* ### Next command register        */
/*2c*/  u_long    nc_dsp;       /* --> Script Pointer               */
/*30*/  u_long    nc_dsps;      /* --> Script pointer save/opcode#2 */
/*34*/  u_long    nc_scratcha;  /* ??? Temporary register a         */
/*38*/  u_char    nc_dmode;
/*39*/  u_char    nc_dien;
/*3a*/  u_char    nc_dwt;
/*3b*/  u_char    nc_dcntl;     /* --> Script execution control     */
        #define   SSM     0x10  /* mod: single step mode            */
        #define   STD     0x04  /* cmd: start dma mode              */
	#define	  NOCOM   0x01	/* cmd: protect sfbr while reselect */
/*3c*/  u_long    nc_adder;

/*40*/  u_short   nc_sien;      /* -->: interupt enable             */
/*42*/  u_short   nc_sist;      /* <--: interupt status             */
        #define   STO     0x0400/* sta: timeout (select)            */
        #define   GEN     0x0200/* sta: timeout (general)           */
        #define   HTH     0x0100/* sta: timeout (handshake)         */
        #define   MA      0x80  /* sta: phase mismatch              */
        #define   CMP     0x40  /* sta: arbitration complete        */
        #define   SEL     0x20  /* sta: selected by another device  */
        #define   RSL     0x10  /* sta: reselected by another device*/
        #define   SGE     0x08  /* sta: gross error (over/underflow)*/
        #define   UDC     0x04  /* sta: unexpected disconnect       */
        #define   RST     0x02  /* sta: scsi bus reset detected     */
        #define   PAR     0x01  /* sta: scsi parity error           */
/*44*/  u_char    nc_slpar;
/*45*/  u_char    nc_45_;
/*46*/  u_char    nc_macntl;
/*47*/  u_char    nc_gpcntl;
/*48*/  u_char    nc_stime0;    /* cmd: timeout for select&handshake*/
/*49*/  u_char    nc_stime1;    /* cmd: timeout user defined        */
/*4a*/  u_char    nc_respid;    /* sta: Reselect-IDs                */
/*4b*/  u_char    nc_4b_;
/*4c*/  u_char    nc_stest0;
/*4d*/  u_char    nc_stest1;
/*4e*/  u_char    nc_stest2;
	#define   ROF     0x40	/* reset scsi offset (after gross error!) */
	#define   EXT     0x02  /* extended filtering                     */
/*4f*/  u_char    nc_stest3;
	#define   TE     0x80	/* c: tolerAnt enable */
	#define   CSF    0x02	/* c: clear scsi fifo */
/*50*/  u_char    nc_sidl;      /* Lowlevel: latched from scsi data */
/*51*/  u_char    nc_51_;
/*52*/  u_char    nc_52_;
/*53*/  u_char    nc_53_;
/*54*/  u_char    nc_sodl;      /* Lowlevel: data out to scsi data  */
/*55*/  u_char    nc_55_;
/*56*/  u_char    nc_56_;
/*57*/  u_char    nc_57_;
/*58*/  u_char    nc_sbdl;      /* Lowlevel: data from scsi data    */
/*59*/  u_char    nc_59_;
/*5a*/  u_char    nc_5a_;
/*5b*/  u_char    nc_5b_;
/*5c*/  u_char    nc_scr0;	/* Working register B               */
/*5d*/  u_char    nc_scr1;	/*                                  */
/*5e*/  u_char    nc_scr2;	/*                                  */
/*5f*/  u_char    nc_scr3;	/*                                  */
/*60*/
};

/*-----------------------------------------------------------
**
**	Utility macros for the script.
**
**-----------------------------------------------------------
*/

#define REGJ(p,r) (offsetof(struct ncr_reg, p ## r))
#define REG(r) REGJ (nc_, r)

#ifndef TARGET_MODE
#define TARGET_MODE 0
#endif

typedef unsigned long ncrcmd;

/*-----------------------------------------------------------
**
**	SCSI phases
**
**-----------------------------------------------------------
*/

#define	SCR_DATA_OUT	0x00000000
#define	SCR_DATA_IN	0x01000000
#define	SCR_COMMAND	0x02000000
#define	SCR_STATUS	0x03000000
#define SCR_ILG_OUT	0x04000000
#define SCR_ILG_IN	0x05000000
#define SCR_MSG_OUT	0x06000000
#define SCR_MSG_IN      0x07000000

/*-----------------------------------------------------------
**
**	Data transfer via SCSI.
**
**-----------------------------------------------------------
**
**	MOVE_ABS (LEN)
**	<<start address>>
**
**	MOVE_IND (LEN)
**	<<dnad_offset>>
**
**	MOVE_TBL
**	<<dnad_offset>>
**
**-----------------------------------------------------------
*/

#define SCR_MOVE_ABS(l) ((0x08000000 ^ (TARGET_MODE << 1ul)) | (l))
#define SCR_MOVE_IND(l) ((0x28000000 ^ (TARGET_MODE << 1ul)) | (l))
#define SCR_MOVE_TBL     (0x18000000 ^ (TARGET_MODE << 1ul))

struct scr_tblmove {
        u_long  size;
        u_long  addr;
};

/*-----------------------------------------------------------
**
**	Selection
**
**-----------------------------------------------------------
**
**	SEL_ABS | SCR_ID (0..7)     [ | REL_JMP]
**	<<alternate_address>>
**
**	SEL_TBL | << dnad_offset>>  [ | REL_JMP]
**	<<alternate_address>>
**
**-----------------------------------------------------------
*/

#define	SCR_SEL_ABS	0x40000000
#define	SCR_SEL_ABS_ATN	0x41000000
#define	SCR_SEL_TBL	0x42000000
#define	SCR_SEL_TBL_ATN	0x43000000

struct scr_tblsel {
        u_char  sel_0;
        u_char  sel_sxfer;
        u_char  sel_id;
        u_char  sel_scntl3;
};

#define SCR_JMP_REL     0x04000000
#define SCR_ID(id)	(((u_long)(id)) << 16)

/*-----------------------------------------------------------
**
**	Waiting for Disconnect or Reselect
**
**-----------------------------------------------------------
**
**	WAIT_DISC
**	dummy: <<alternate_address>>
**
**	WAIT_RESEL
**	<<alternate_address>>
**
**-----------------------------------------------------------
*/

#define	SCR_WAIT_DISC	0x48000000
#define SCR_WAIT_RESEL  0x50000000

/*-----------------------------------------------------------
**
**	Bit Set / Reset
**
**-----------------------------------------------------------
**
**	SET (flags {|.. })
**
**	CLR (flags {|.. })
**
**-----------------------------------------------------------
*/

#define SCR_SET(f)     (0x58000000 | (f))
#define SCR_CLR(f)     (0x60000000 | (f))

#define	SCR_CARRY	0x00000400
#define	SCR_TRG		0x00000200
#define	SCR_ACK		0x00000040
#define	SCR_ATN		0x00000008




/*-----------------------------------------------------------
**
**	Memory to memory move
**
**-----------------------------------------------------------
**
**	COPY (bytecount)
**	<< source_address >>
**	<< destination_address >>
**
**-----------------------------------------------------------
*/

#define SCR_COPY(n) (0xc0000000 | (n))

/*-----------------------------------------------------------
**
**	Register move and binary operations
**
**-----------------------------------------------------------
**
**	SFBR_REG (reg, op, data)        reg  = SFBR op data
**	<< 0 >>
**
**	REG_SFBR (reg, op, data)        SFBR = reg op data
**	<< 0 >>
**
**	REG_REG  (reg, op, data)        reg  = reg op data
**	<< 0 >>
**
**-----------------------------------------------------------
*/

#define SCR_SFBR_REG(reg,op,data) \
        (0x68000000 | (REG(reg) << 16ul) | (op) | ((data)<<8ul))

#define SCR_REG_SFBR(reg,op,data) \
        (0x70000000 | (REG(reg) << 16ul) | (op) | ((data)<<8ul))

#define SCR_REG_REG(reg,op,data) \
        (0x78000000 | (REG(reg) << 16ul) | (op) | ((data)<<8ul))

#define      SCR_LOAD   0x00000000
#define      SCR_SHL    0x01000000
#define      SCR_OR     0x02000000
#define      SCR_XOR    0x03000000
#define      SCR_AND    0x04000000
#define      SCR_SHR    0x05000000
#define      SCR_ADD    0x06000000
#define      SCR_ADDC   0x07000000

/*-----------------------------------------------------------
**
**	FROM_REG (reg)		  reg  = SFBR
**	<< 0 >>
**
**	TO_REG	 (reg)		  SFBR = reg
**	<< 0 >>
**
**	LOAD_REG (reg, data)	  reg  = <data>
**	<< 0 >>
**
**	LOAD_SFBR(data) 	  SFBR = <data>
**	<< 0 >>
**
**-----------------------------------------------------------
*/

#define	SCR_FROM_REG(reg) \
	SCR_REG_SFBR(reg,SCR_OR,0)

#define	SCR_TO_REG(reg) \
	SCR_SFBR_REG(reg,SCR_OR,0)

#define	SCR_LOAD_REG(reg,data) \
	SCR_REG_REG(reg,SCR_LOAD,data)

#define SCR_LOAD_SFBR(data) \
        (SCR_REG_SFBR (gpreg, SCR_LOAD, data))

/*-----------------------------------------------------------
**
**	Waiting for Disconnect or Reselect
**
**-----------------------------------------------------------
**
**	JUMP            [ | IFTRUE/IFFALSE ( ... ) ]
**	<<address>>
**
**	JUMPR           [ | IFTRUE/IFFALSE ( ... ) ]
**	<<distance>>
**
**	CALL            [ | IFTRUE/IFFALSE ( ... ) ]
**	<<address>>
**
**	CALLR           [ | IFTRUE/IFFALSE ( ... ) ]
**	<<distance>>
**
**	RETURN          [ | IFTRUE/IFFALSE ( ... ) ]
**	<<dummy>>
**
**	INT             [ | IFTRUE/IFFALSE ( ... ) ]
**	<<ident>>
**
**	INT_FLY         [ | IFTRUE/IFFALSE ( ... ) ]
**	<<ident>>
**
**	Conditions:
**	     WHEN (phase)
**	     IF   (phase)
**	     CARRY
**	     DATA (data, mask)
**
**-----------------------------------------------------------
*/

#define SCR_JUMP        0x80080000
#define SCR_JUMPR       0x80880000
#define SCR_CALL        0x88080000
#define SCR_CALLR       0x88880000
#define SCR_RETURN      0x90080000
#define SCR_INT         0x98080000
#define SCR_INT_FLY     0x98180000

#define IFFALSE(arg)   (0x00080000 | (arg))
#define IFTRUE(arg)    (0x00000000 | (arg))

#define WHEN(phase)    (0x00030000 | (phase))
#define IF(phase)      (0x00020000 | (phase))

#define DATA(D)        (0x00040000 | ((D) & 0xff))
#define MASK(D,M)      (0x00040000 | (((M ^ 0xff) & 0xff) << 8ul)|((D) & 0xff))

#define CARRYSET       (0x00200000)

/*-----------------------------------------------------------
**
**	SCSI  constants.
**
**-----------------------------------------------------------
*/

/*
**	Messages
*/

#define	M_COMPLETE	(0x00)
#define	M_EXTENDED	(0x01)
#define	M_SAVE_DP	(0x02)
#define	M_RESTORE_DP	(0x03)
#define	M_DISCONNECT	(0x04)
#define	M_ID_ERROR	(0x05)
#define	M_ABORT		(0x06)
#define	M_REJECT	(0x07)
#define	M_NOOP		(0x08)
#define	M_PARITY	(0x09)
#define	M_LCOMPLETE	(0x0a)
#define	M_FCOMPLETE	(0x0b)
#define	M_RESET		(0x0c)
#define	M_ABORT_TAG	(0x0d)
#define	M_CLEAR_QUEUE	(0x0e)
#define	M_INIT_REC	(0x0f)
#define	M_REL_REC	(0x10)
#define	M_TERMINATE	(0x11)
#define	M_SIMPLE_TAG	(0x20)
#define	M_HEAD_TAG	(0x21)
#define	M_ORDERED_TAG	(0x22)
#define	M_IDENTIFY   	(0x80)

#define	M_X_SDTR	(0x01)

/*
**	Status
*/

#define	S_GOOD		(0x00)
#define	S_CHECK_COND	(0x02)
#define	S_COND_MET	(0x04)
#define	S_BUSY		(0x08)
#define	S_INT		(0x10)
#define	S_INT_COND_MET	(0x14)
#define	S_CONFLICT	(0x18)
#define	S_TERMINATED	(0x20)
#define	S_QUEUE_FULL	(0x28)
#define	S_ILLEGAL	(0xff)

#endif /*__NCR_REG_H__*/
