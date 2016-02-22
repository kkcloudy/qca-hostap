/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */


#ifndef ATH_ME_H
#define ATH_ME_H
//#include "stdint.h"
#include "math.h"
#include <wpc_mgr.h>


#define int8        int8_t
#define int16       int16_t     
#define int32       int32_t     
#define uint8       u_int8_t     
#define uint16      u_int16_t     
#define uint32      u_int32_t     

typedef float  FLT;
typedef double DBL;

/****** Definitions ***********************************************************/
#define MAX_VALUE                   (int)511 /* max value of Re/Im component */
#define TEN_BIT_VALUE               (int)1024 /* 2^10 */
#define NUM_OFDM_TONES_ACK_FRAME    52
#define NUM_OFDM_TONES_UNI_FRAME    56
#define BW40                        0
#define RESOLUTION_IN_BITS          10
#define NUM_RX_CHAINS               3
#define NUM_TONES                   (NUM_OFDM_TONES_ACK_FRAME * (BW40 + 1))
#define H_IN_BITS                   (NUM_TONES * NUM_RX_CHAINS * 2 * RESOLUTION_IN_BITS) /* sz cir in bits */
#define H_IN_DWORDS                 ((H_IN_BITS+31)/32) /* # of 32 bit words */
#define FFTSZ                       (128) /* FFTSZ = 2^7 */
#define LOG2FFTSZ                   (7)   /* log2(128) = 7 */
#define TOA_SEARCH_RANGE            20 /* max distance from maximal path over which to search for fap */
#define PATH_MIN_PWR_THRESH         ((float)(0.09)) /* threshold for fap search (path power>max power*thr) */
// Params
#define CLK_NS                      (double) 22.7272 // Clock time in nanosec 1/44*1e(-6)*1e9 = 1/44*1000 = 22.7272
#define TOA_COEFFICIENT             45
#define CH_SYM_COEF                 1
#define RTT_EXC_THR                 150
#define MAX_OUTLIERS                10 // this is the maximum outliers in one measurements 
#define TYPE1PAYLDLEN               390
/*
 * Constant definitions
 */

#define C_PI      3.1415926535898   /* From ICD */
#define FFT_MAX_NU 15  /* 2**15 = 32768 */
#define C_TWO_PI (DBL)(C_PI*2.0) 


/************************************************************************************/

/* Structure used to process 16 bit complex quantities */
typedef struct
{
  int16 x_I;
  int16 x_Q;
} CplxS16;

#ifdef ATH_WPC_ME_DEBUG
/* Fucntions for debugging*/
void wpc_rtte_readinput(u_int8_t *cd);
void wpc_rtte_dumpoutput(u_int32_t *PowerProfile, u_int16_t chainNumber);
#endif 


/* Function     : BitReverse
 * Argument     : Bit reverse sequence and the index 
 * Functionality: Get the index for butterfly multiplication for FFT
 * Retrun       : the index for butterfly multiplication
 */
uint32 wpc_rtte_bit_reverse( const uint16 *p_BitReverse, uint32 q_X );

/* Function     : wpc_rtte_ifft
 * Argument     : Processed Channel data,  fftPwr(calculated here), 
 *                twiddle factor (FFT), p_bitRev (bit reverse seq. for FFT)
 *                w_Nu: log(FFTSZ)
 * Functionality: Calculate IFFT from channel dump. 
 * Return       : Void
 */

void wpc_rtte_ifft(int16_t *chanData,  u_int32_t *fftPwr, int16_t *p_twiddle, u_int16_t *p_bitRev, u_int16_t w_Nu); 

/* Function     : wpc_rtte_populate_channel_dump
 * Arguments    : populate the channel dump, num of rx chain, current chain data, 
 *                log(FFTSZ) 
 * Functionality: To arrange channel dump in correct format to do IFFT
 * Return       : Rearranged channel dumps for IFFT
 */
void wpc_rtte_populate_channel_dump(int16_t *hTemp, int16_t *chanData, u_int16_t nRxChains, u_int16_t curr_chain, u_int16_t w_Nu);

/* Function     :   wpc_rtte__proccd
 * Arguments    :   wpc_probe_data -> this the channel dump we get from the driver.
 *                  wpc_pkt_corr_param -> correction parameters for processing CD.
 * Functionality:   To process the Channel Dump (CD) to get the IFFT.
 * Return       :   Retuns the pointer to processed channel dump.
 */
int16_t* wpc_rtte__proccd(wpc_probe_data *ppd, u_int16_t w_nRxChains);

/* Function     : wpc_rtte_locate_toa
 * Arguments    : powProfile -> Power Spectrum from IIFT
                  toa -> to be updated in the function
                  toa_sp -> toa for strongest path
 * Functionality: To calculate the toa correction factor
 * Return       : Void
 */
void  wpc_rtte_locate_toa(u_int32_t *powProfile, int16_t *toa, int16_t *toa_sp, int16_t w_Nu);

/* Fucntion     : wpc_rtte_get_rtt
 * Arguments    : ppd -> all the information of one pkt is stored here.
 *                toa -> toa correction factor we got
 *                toa_sp -> strongest path toa correction we got
 * Functionality: To take toa and then get the rtt correction.
 * Retun        : Void
 */
void wpc_rtte_get_rtt(wpc_probe_data *ppd, u_int16_t nRxChains);


/*
 ******************************************************************************
 * wpc_rtte_init_fft
 *
 * Function description:
 *  wpc_rtte_init_fft initializes the lookup tables used by the 4096 point FFT routine.
 *
 * Parameters:
 *  p_Cos - Pointer to array of S16's to hold cosine table. Must be at least 2^w_Nu
 *  long.
 *
 *  p_BitReverse - Pointer to an array of U16's to hold bit reverse table. Must be at least
 *   2^(w_Nu / 2) long.
 *
 *  p_Hanning - Pointer to an array of S16's to hold the first half of a Hanning table.
 *   must be at least 2^7 U16's long.
 *
 *  w_Nu - 2^w_Nu specifies the number of points to be used in the FFT. For example, for a
 *   4096 point FFT, w_Nu would equal 12.
 *
 * Return value:
 *  0 if successful, 0xFFFF if unsuccessful
 *
 ******************************************************************************
*/

uint16 wpc_rtte_init_fft( int16 *p_Cos, uint16 *p_BitReverse, uint16 w_Nu );

/*
 ******************************************************************************
 * wpc_rtte_fft
 *
 * Function description:
 *  wpc_rtte_fft computes a 2^w_Nu point FFT on a block of complex S16 samples. The
 * FFT is performed in-place ( FFT results overwrite original sample data ).
 * This routine requires the block of samples to be an interleaved set of I and
 * Q samples where the start of the block is an I sample.
 *
 * Parameters:
 *  p_Cplx - Pointer to a block of interleaved (I/Q) complex samples.
 *  p_CosTable - Pointer to a 2^w_Nu point cosine table
 *  p_BitReverse - Pointer to a 2^7 point bit reverse table
 *  w_Nu - Power of two corresponding to the number of points in the FFT
 *
 * Return value:
 * 0 if successful, 0xFFFF if unsuccessful
 *
 ******************************************************************************
*/
uint16 wpc_rtte_fft( CplxS16 *p_Cplx, const int16 *p_CosTable, const uint16 *p_BitReverse, uint16 w_Nu );


/*
 ******************************************************************************
 * wpc_rtte_fft2_power_spectrum
 *
 * Function description:
 *
 * Converts a set of N complex FFT results into a power spectrum.
 *
 * Parameters:
 * p_Cplx - Pointer to the first complex FFT value 
 *  w_FpAdjust - Accumulated block fp adjustment from FFT processing
 * p_Power - Pointer to location to store power spectrum ( this pointer can point
 *  to the same place as p_Cplx if it is desired for the power spectrum to overwrite
 *  the FFT results ).
 * w_Nu - Power of 2 corresponding to number of complex samples 
 *  u_Init - FALSE sums to FFT power sample to the power array
 *
 * Return value:  
 *  None.
 *
 ******************************************************************************
*/

void wpc_rtte_fft2_power_spectrum( const CplxS16 *p_Cplx, int16 x_FpAdjust, FLT *p_Power, uint16 w_Nu, uint8 u_Init );

/* Function     : wpc_rtte_block_fp_adjust
 * Arguments    : CplxS16 ifft seq, FFTSZ, shift got from fft
 * Fucntionality: To adjust the values for fft. 
 * Return       : void
 */ 
void wpc_rtte_block_fp_adjust( CplxS16 *p_Cplx, uint32 q_N, uint32 q_Shift );


#endif
