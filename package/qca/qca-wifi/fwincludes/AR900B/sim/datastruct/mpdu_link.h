// Copyright (c) 2012 Qualcomm Atheros, Inc.  All rights reserved.
// $ATH_LICENSE_HW_HDR_C$
//
// DO NOT EDIT!  This file is automatically generated
//               These definitions are tied to a particular hardware layout


#ifndef _MPDU_LINK_H_
#define _MPDU_LINK_H_
#if !defined(__ASSEMBLER__)
#endif

// ################ START SUMMARY #################
//
//	Dword	Fields
//	0	mpdu_length[13:0], reserved_0a[15:14], next_mpdu_index[29:16], reserved_0b[31:30]
//
// ################ END SUMMARY #################

#define NUM_OF_DWORDS_MPDU_LINK 1

struct mpdu_link {
    volatile uint32_t mpdu_length                     : 14, //[13:0]
                      reserved_0a                     :  2, //[15:14]
                      next_mpdu_index                 : 14, //[29:16]
                      reserved_0b                     :  2; //[31:30]
};

/*

mpdu_length
			
			MPDU Frame Length in bytes.
			
			This is the full MPDU length, which includes all
			(A-)MSDU frames, header conversion, encryption, FCS, etc.
			<legal 1-16000>

reserved_0a
			
			<legal 0>

next_mpdu_index
			
			Index of the next MPDU link data structure that
			represents the next MPDU in the queue.
			
			A value of 0x0represents the 'Null pointer' and is used
			when no other MPDU link data structure is connected to this
			one.

reserved_0b
			
			<legal 0>
*/


/* Description		MPDU_LINK_0_MPDU_LENGTH
			
			MPDU Frame Length in bytes.
			
			This is the full MPDU length, which includes all
			(A-)MSDU frames, header conversion, encryption, FCS, etc.
			<legal 1-16000>
*/
#define MPDU_LINK_0_MPDU_LENGTH_OFFSET                               0x00000000
#define MPDU_LINK_0_MPDU_LENGTH_LSB                                  0
#define MPDU_LINK_0_MPDU_LENGTH_MASK                                 0x00003fff

/* Description		MPDU_LINK_0_RESERVED_0A
			
			<legal 0>
*/
#define MPDU_LINK_0_RESERVED_0A_OFFSET                               0x00000000
#define MPDU_LINK_0_RESERVED_0A_LSB                                  14
#define MPDU_LINK_0_RESERVED_0A_MASK                                 0x0000c000

/* Description		MPDU_LINK_0_NEXT_MPDU_INDEX
			
			Index of the next MPDU link data structure that
			represents the next MPDU in the queue.
			
			A value of 0x0represents the 'Null pointer' and is used
			when no other MPDU link data structure is connected to this
			one.
*/
#define MPDU_LINK_0_NEXT_MPDU_INDEX_OFFSET                           0x00000000
#define MPDU_LINK_0_NEXT_MPDU_INDEX_LSB                              16
#define MPDU_LINK_0_NEXT_MPDU_INDEX_MASK                             0x3fff0000

/* Description		MPDU_LINK_0_RESERVED_0B
			
			<legal 0>
*/
#define MPDU_LINK_0_RESERVED_0B_OFFSET                               0x00000000
#define MPDU_LINK_0_RESERVED_0B_LSB                                  30
#define MPDU_LINK_0_RESERVED_0B_MASK                                 0xc0000000


#endif // _MPDU_LINK_H_
