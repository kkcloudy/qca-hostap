/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
#include <sys/select.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include "ieee80211_wpc.h"
#include "wpc_mgr.h"
#include "wpc_rtte_me.h"
#define PRIN_LOG(format, args...) printf(format "", ## args)

static int16_t ptwiddle[FFTSZ];
static u_int16_t pbitRev[FFTSZ];
#ifdef ATH_WPC_ME_DEBUG

void wpc_rtte_readinput(u_int8_t *cd)
{
//TBR
//Read H from channel dump file
    int16_t i =0;
    int16_t w_Nu = LOG2FFTSZ;
    u_int32_t q_N = 1 << w_Nu;
    u_int32_t ath_me_h_in_mem[TYPE1PAYLDLEN];
//    ath_me_h_in_mem = (u_int32_t *) cd;
    FILE *file = fopen("cd_fft_ap.txt", "r");
    while(fscanf(file, "%x", &ath_me_h_in_mem[i]) != EOF) {
        i++;
    }
    for (i = 0; i < TYPE1PAYLDLEN; i++) {
        cd[i] = (u_int8_t)ath_me_h_in_mem[i];
    }
    fclose(file);
}

void wpc_rtte_dumpoutput(u_int32_t *PowerProfile, u_int16_t chainNumber)
{
    int i;
    u_int32_t q_N = FFTSZ; 
    FILE * file = fopen("cir.txt", "a+");
    fprintf(file,"CIR for chain %d \n", chainNumber);
    
    for(i=0; i < q_N; i++) {
        fprintf(file, "%u\n", PowerProfile[i]);
    }
    fprintf(file,"\n");
    fclose(file);
    return ;

}
#endif 

/* Since all the byte manipulation has been done as big endian we need 
 * to change the memory data to bigendian 
 */
u_int32_t wpc_rtte_reverse_bit(u_int32_t temp){
    u_int32_t b0, b1, b2, b3;
    b0 = (temp & 0x000000ff) >> 0;
    b1 = (temp & 0x0000ff00) >> 8;
    b2 = (temp & 0x00ff0000) >> 16;
    b3 = (temp & 0xff000000) >> 24;
    return ((b0 <<24) + (b1 <<16) + (b2 <<8) + (b3 << 0));
}

void wpc_rtte_divide_by_N(CplxS16 *p_Cplx, u_int16_t w_Nu, u_int16_t q_N)
{
    while(q_N--) {
        p_Cplx->x_I = p_Cplx->x_I >> w_Nu; //Divide by 2^w_Nu
        p_Cplx->x_Q = p_Cplx->x_Q >> w_Nu; //Divide by 2^w_Nu
        p_Cplx++;
    }
}
/* Function     : wpc_rtte_complex_conjugate
 * Argument     : p_Cplx pointer to the array of complex numbers to be conjugated. 
 *                q_N is hte size of the FFT size
 * Functionality: To do the complex conjugate. Use here for doing IFFT using FFT routine. 
 * Return       : Void. 
 */
void wpc_rtte_complex_conjugate(CplxS16 *p_Cplx, u_int16_t q_N)
{
    while(q_N--){
        p_Cplx->x_I = p_Cplx->x_I;
        p_Cplx->x_Q = -1 * p_Cplx->x_Q;
        p_Cplx++;
    }
    
}
/* To calculatet the power spectrum of a complex number */
void wpc_rtte_power_profile(CplxS16 *p_Cplx, double *delayPowerProfile, u_int16_t q_N)
{   
    double *p_t;
    p_t = delayPowerProfile;
    while(q_N--) {
        *delayPowerProfile = (double ) (p_Cplx->x_I*p_Cplx->x_I + p_Cplx->x_Q*p_Cplx->x_Q);
        delayPowerProfile++;
        p_Cplx++;
    
    }
}


int16_t* wpc_rtte__proccd(wpc_probe_data *ppd, u_int16_t nRxChains)
{
    int16_t i, j;
    int hTempIndex = 0;
    int32_t     *hInMem = (int32_t *)ppd->cd;
    int16_t     *hTemp;
    /* Reversing the endianess */
#ifndef ATH_WPC_ME_DEBUG_FFT
    for (i =0; i < 128; i++){
        hInMem[i] = wpc_rtte_reverse_bit(hInMem[i]);
    }
#endif
    hTemp  = (int16_t *) malloc(sizeof(int16_t)*((H_IN_DWORDS/5)+1)*8*2); /* (# 4byte words)/5 plus one gives the # of groups x 8 tones/group x 2 components/tone */
    memset(hTemp, 0x0000, (sizeof(int16_t)*((H_IN_DWORDS/5)+1)*8*2)); 
    if(hTemp == NULL) { printf(">>> 2MALLOC failed!!!\n"); }

    /* rearrange info in a single array with Re/Im sequence for each tone */
    for( i=0; i<H_IN_DWORDS; i+=5 ) {
        hTemp[hTempIndex]   = hInMem[i]     & 0x3ff;
        hTemp[hTempIndex+1] = hInMem[i]>>10 & 0x3ff;
        hTemp[hTempIndex+2] = hInMem[i]>>20 & 0x3ff;
        hTemp[hTempIndex+3] = ((hInMem[i+1] & 0xff)<<2) | (hInMem[i]>>30 & 0x3);

        hTemp[hTempIndex+4] = hInMem[i+1]>>8 & 0x3ff;
        hTemp[hTempIndex+5] = hInMem[i+1]>>18 & 0x3ff;
        hTemp[hTempIndex+6] = ((hInMem[i+2] & 0x3f)<<4) | (hInMem[i+1]>>28 & 0xf);

        hTemp[hTempIndex+7] = hInMem[i+2]>>6 & 0x3ff;
        hTemp[hTempIndex+8] = hInMem[i+2]>>16 & 0x3ff;

        hTemp[hTempIndex+10] = hInMem[i+3]>>4 & 0x3ff;
        hTemp[hTempIndex+11] = hInMem[i+3]>>14 & 0x3ff;
        hTemp[hTempIndex+12] = ((hInMem[i+4] & 0x3)<<8) | (hInMem[i+3]>>24 & 0xff);

        hTemp[hTempIndex+13] = hInMem[i+4]>>2 & 0x3ff;
        hTemp[hTempIndex+14] = hInMem[i+4]>>12 & 0x3ff;
        hTemp[hTempIndex+15] = hInMem[i+4]>>22 & 0x3ff;

        hTempIndex = hTempIndex + 16;
    }
    /* 10 bit number includes sign, figure out which should be capped */
    for( i=0; i<NUM_TONES; i++ ) {
        for( j=0; j<(nRxChains*2); j++ ) {
            if( hTemp[nRxChains*i*2+j] > MAX_VALUE ) {
                hTemp[nRxChains*i*2+j] = hTemp[nRxChains*i*2+j]-TEN_BIT_VALUE;
            }
        }

   }
    return hTemp;
 
}
void wpc_rtte_populate_channel_dump(int16_t *hTemp, int16_t *chanData, u_int16_t nRxChains, u_int16_t j, u_int16_t w_Nu)
{
    u_int16_t i = 0, k =0;
    int avgRe = 0;
    int avgIm = 0;
    int halfTones;
    int16_t *hRe;
    int16_t *hIm;
    u_int32_t q_N;
    halfTones = NUM_TONES/2;

    q_N = 1 << w_Nu;
    hRe = (int16_t *) malloc(sizeof(int16_t)*q_N);
    hIm = (int16_t *) malloc(sizeof(int16_t)*q_N);
    hRe[0] = 0;
    hIm[0] = 0;
    /* populate from 1 to halfTones(26) */
    for( i=1; i<(halfTones+1); i++ ) {
        hRe[i] = hTemp[nRxChains*(halfTones+i-1)*2+j*2+1];
        hIm[i] = hTemp[nRxChains*(halfTones+i-1)*2+j*2];
    }
        
    /* between halfTones(27) and fftSz(101), we have ... */
    /* zero padding */
    for( i=(halfTones + 1); i<(q_N-halfTones); i++ ) {
        hRe[i] = avgRe;
        hIm[i] = avgIm;
    }   
    /* populate from (FFTSZ-halfTones)(102) to FFTSZ(127) */
    k=0;
    for( i=(q_N -halfTones); i<q_N; i++ ) {
        hRe[i] = hTemp[nRxChains*k*2+j*2+1];
        hIm[i] = hTemp[nRxChains*k*2+j*2];
        k++;
    }

    /* set up input for ifft */
    for( i=0; i< q_N; i++ ) {
        chanData[2*i] = hRe[i];
        chanData[2*i +1]   = 1*hIm[i]; /* conjugate of input */
    }
    free(hRe);
    free(hIm);
 
}

void wpc_rtte_calculate_ftoa(wpc_probe_data *ppd, u_int16_t nRxChains) 
{
#ifdef ATH_WPC_ME_DEBUG_FFT
    u_int16_t i =0;
#endif 
    u_int16_t  j = 0;
    u_int32_t q_N;
    int16_t *hTemp;
    int16_t *cData;
    int16_t *toa_corr;
    int16_t *toa_sp_corr;
    u_int32_t *fftPwr;
    u_int16_t w_Nu = 7;

    q_N = 1 << w_Nu;
    toa_corr = ppd->toa_corr;
    toa_sp_corr = ppd->toa_sp_corr;
    fftPwr = (u_int32_t *) malloc(sizeof(u_int32_t)*q_N);
    cData = (int16_t *) malloc(sizeof(int16_t)*2*q_N);

    /* Getting the processed Channel dump */
    hTemp = wpc_rtte__proccd(ppd, nRxChains);
    
    wpc_init_rtte();

    for( j=0; j<nRxChains; j++ ) { /* iterate over the # of receive chains */

        memset(fftPwr, 0x0, (sizeof(u_int32_t)*q_N)); 
        memset(cData, 0x0, (sizeof(int16_t)*q_N*2)); 

        /* Populating channel dump for ifft */
        wpc_rtte_populate_channel_dump(hTemp, cData, nRxChains, j, w_Nu); 
        /* Calculating Delay power profile */
        if(ptwiddle == NULL || pbitRev == NULL) {
            PRIN_LOG("ERROR: RTT Engine is not initialised \n ");
            return;
        }
            
        wpc_rtte_ifft(cData, fftPwr, ptwiddle, pbitRev, w_Nu);
        /* Calculating correction factor for individual RX chains */
        wpc_rtte_locate_toa(fftPwr, &toa_corr[j], &toa_sp_corr[j], w_Nu);
#ifdef ATH_WPC_ME_DEBUG_FFT
        wpc_rtte_dumpoutput(fftPwr, j);
#endif 
    } // for( j=0; j<nRxChains; j++ ) 
    wpc_rtte_get_rtt(ppd, nRxChains);
    free(fftPwr);
    free(cData);
    free(hTemp);
}

void wpc_rtte_ifft(int16_t *chanData,  u_int32_t *fftPwr, int16_t *p_twiddle, u_int16_t *p_bitRev, u_int16_t w_Nu) 
{
    u_int16_t i = 0;
    CplxS16 *pX, *pXT;
    u_int16_t ws;
    u_int32_t q_N;

    q_N = 1 << w_Nu;
    pX = (CplxS16* )malloc(sizeof(CplxS16)*q_N);
    pXT = pX;
     /* Reorder the input for IFFT, store it with real and imag part */
    for( i=0; i<q_N; i++ ) {
        pX->x_I = chanData[2*i];
        pX->x_Q = chanData[2*i+1];
        pX++;
    }
    pX = pXT;
    wpc_rtte_complex_conjugate(pX, q_N);
    ws = wpc_rtte_fft(pX, p_twiddle, p_bitRev, w_Nu);
     /* compute power of ifft result */
    for(i=0; i < q_N; i++) {
        fftPwr[i] = (u_int32_t)(pX->x_I*pX->x_I + pX->x_Q*pX->x_Q);
        pX++;
    }
    pX = pXT;
    free(pX);
}
/* This takes the minimum RTT */ 
void wpc_rtte_get_rtt(wpc_probe_data *ppd, u_int16_t nRxChains)
{
    int i;
    if(nRxChains == 0) {
        PRIN_LOG("Error: %s Min number of RxChain is 1 \n", __func__);
        return;
    }
    for( i = 0; i < nRxChains; i++) {
        ppd->rtt[i] = ((double)ppd->toa - (double) ppd->tod - CH_SYM_COEF*ppd->toa_corr[i]*1.1)*CLK_NS;
        if(i == 0) // initialising final rtt with rtt of chain 0
            ppd->frtt = ppd->rtt[i];
        if(ppd->frtt >  ppd->rtt[i]) // choosing the min rtt from all of the 3 chians. 
            ppd->frtt = ppd->rtt[i]; // more sophisticated selection is done using outlier detection 
            
        PRIN_LOG("%s: RTT[%d]: %f ns \n",__func__, i, ppd->rtt[i]);
    }
    PRIN_LOG("%s: Final RTT: %f ns \n",__func__, ppd->frtt);
}



void wpc_rtte_locate_toa(u_int32_t *powProfile, int16_t *toa, int16_t *toa_sp, int16_t w_Nu)
{
    int i = 0, k = 0, ind =0 ;
    FLT thr1, thr;
    double maxv;
    int j[TOA_SEARCH_RANGE]; // 20 indexes previous to max Power 
    double P2[TOA_SEARCH_RANGE]; // 20 power values before max power
    int p[TOA_SEARCH_RANGE], maxp, p2_index[TOA_SEARCH_RANGE]; // position of powers above threoshold
    int pp; // power position for correction 
    int  maxi = 0; // max Power, max Power index
    int32_t q_N = 1 << w_Nu;
    double meanPwr = 0.0, mMeanPwr = 0.0;

    /* Finding max Power and its position */
    maxv = (double) powProfile[0];
    maxi = 0;
    *toa = 0;
    *toa_sp = 0;
    for (i = 1; i < q_N; i++){
        if(maxv < powProfile[i]) {
            maxv =  (double) powProfile[i];
            maxi = i;
        }
    }
    /* calculate Mean power */
    for (i =0; i < q_N; i++)
        meanPwr += (double) powProfile[i];
    meanPwr = meanPwr/q_N;
    
    /* Calculating mean of Power less than avg.Pwr *coeff*/
    for(i = 0; i < q_N; i++){
        if(powProfile[i] < meanPwr){
            mMeanPwr += (double) powProfile[i];
            k++;
        }
    }
    if(k) 
        mMeanPwr = mMeanPwr/k;
    else 
        mMeanPwr = 0;
    PRIN_LOG("%s: MaxP[@%d]: %f, MeanP: %f, MeanPMP[%d_samples]: %f\n",__func__,maxi, maxv, meanPwr, k, mMeanPwr );
    k = 0; //re-initializing k = 0;
    /* Calculating thresholds */
    thr1 = maxv *0.1;
    thr = (mMeanPwr*TOA_COEFFICIENT); 
    if(thr1 < thr)
        thr = thr1/maxv;
    else 
        thr = thr/maxv;
    /* Getting Indexes for power */
    for(i = 0; i < TOA_SEARCH_RANGE; i++){   
        j[i] = maxi - (i+1);
        if(j[i] < 0)
            j[i] = j[i] + q_N;
        P2[i] = powProfile[j[i]]; 
        p2_index[i] = j[i];
        k++;
    }
    maxp = 0;
    ind = 0;
    maxp = p2_index[0];
    for (i = 0; i < k; i++) {
        if(P2[i] > thr*maxv) {
            p[i] = p2_index[i];
            if(maxp < p[i])
                maxp = p[i];
            ind++;
        }
    }
    if(ind == 0)
        *toa = 0;
    else {
        pp = maxp;
        *toa = -1* pp;
        if((-1* pp) < -q_N/2)
            *toa += q_N;
    }
    *toa_sp = -1* maxi;
    if((-1*maxi) < -q_N/2)
        *toa_sp += q_N;
    PRIN_LOG("%s: toa: %d, tos_sp: %d\n", __func__, *toa, *toa_sp);

}



/*
 ******************************************************************************
 * wpc_rtte_init_fft
 *
 * Function description:
 * wpc_rtte_init_fft initializes the lookup tables used by the 2^w_Nu point FFT routine. 
 *
 * Parameters:
 * p_Cos - Pointer to array of int16's to hold cosine table. Must be at least 2^w_Nu
 *  long.
 * 
 *  p_BitReverse - Pointer to an array of uint16's to hold bit reverse table. Must have
 *  at least 2^w_Nu elements
 *
 *  w_Nu - 2^w_Nu specifies the number of points to be used in the FFT. For example, for a
 *   4096 point FFT, w_Nu would equal 12.
 *
 * Return value:  
 *  0 if successful, 0xFFFF if unsuccessful
 *
 ******************************************************************************
*/

uint16 wpc_rtte_init_fft( int16 *p_Cos, uint16 *p_BitReverse, uint16 w_Nu )
{
    uint32 q_I;
    int16 *p_Read;
    uint32 q_N =  1 << w_Nu;

    if( w_Nu > FFT_MAX_NU )
        return( 0xffff );

    /* Generate N sample cosine table. To do this, we will compute the first
    quarter wave of the cosine, then mirror/invert accordingly to obtain the
    full cosine */

    /* Generate samples from 0 to PI/2 */
    for ( q_I = 0; q_I < (q_N >> 2); q_I++ ){
      *p_Cos++ = (int16) ( 32767 * cos( C_TWO_PI * q_I * ( 1.0 / (FLT) q_N ) ) );
    }

    *p_Cos++ = 0;

    /* Mirror and Invert above samples to obtain PI/2 to PI*/
    p_Read = p_Cos - 2;

    for ( q_I = 0; q_I < ( (q_N >> 2) - 1 ); q_I++ ){
        *p_Cos++ = -(*p_Read--);
    }

    *p_Cos++ = -32767;

    /* Mirror the samples from 0 to PI to obtain PI to 2PI region */
    p_Read = p_Cos - 2;

    for ( q_I = 0; q_I < ( (q_N >> 1) - 1 ); q_I++ ){
        *p_Cos++ = (*p_Read--);
    }

    /* Generate a 2^w_Num element Bit Reverse Lookup Table. */
    for( q_I = 0; q_I < q_N; q_I++ ) {
         uint32 q_K, q_BitRev, q_Bit;

        for( q_Bit = q_I, q_BitRev = 0, q_K = w_Nu; q_K; q_K-- ){
            q_BitRev = (q_BitRev << 1) | (q_Bit & 1);
            q_Bit >>= 1;
        } 

        *p_BitReverse++ = (uint16)q_BitRev;
    }

    return(0);
}


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

void wpc_rtte_fft2_power_spectrum( const CplxS16 *p_Cplx, int16 x_FpAdjust, FLT *p_Power, uint16 w_Nu, uint8 u_Init )
{
FLT f_Power;
FLT f_FpAdjust;

 uint32 q_Cnt;
 uint32 q_N = 1 << w_Nu;
  
  /* A explanatory note on the use of FLT rather than DBL.
  
     The maximum amplitude that can be output from the 32k point FFT using CplxS16 is
     sqrt(2).2**15 << 15 = sqt(2).2**30. (In this case x_FpAdjust = 15).
     
     The power sample is the square of this. Maximum power sample is therefore
     2**61.
     
     The power samples are accumumated in the FLT data type. The maximum FLT value
     is 3.4e36.
     
     Therefore, we can accumulate (3.4e36 / 2**61) = 1.5e18 samples before risk of
     FLT overflow. 
     
     f_FpAdjust will be used to remove the aggregate block fp accumulated during 
     the FFT processing. The multiply by 2 is because this correction is applied
     to the power and not the amplitude. 
     
     f_FpAdjust = 2**(2 * x_FpAdjust) */
  f_FpAdjust = (FLT) ldexp( 1.0, 2*x_FpAdjust );

 /* Compute Power Spectrum */
 for ( q_Cnt = q_N; q_Cnt; q_Cnt--, p_Cplx++ )
 {
    /*lint -e{737} : Loss of sign in promotion from int to unsigned long */
    f_Power = (FLT) ((uint32)(p_Cplx->x_I*p_Cplx->x_I) + (p_Cplx->x_Q*p_Cplx->x_Q));
    f_Power *= f_FpAdjust;
    
    if( u_Init )
     *p_Power++ = f_Power;
    else
     *p_Power++ += f_Power;
 }
}


/*
 ******************************************************************************
 * wpc_rtte_fft 
 *
 * Function description:
 * wpc_rtte_fft computes a 2^w_Nu point FFT on a block of complex int16 samples. The
 * FFT is performed in-place ( FFT results overwrite original sample data ).
 * This routine requires the block of samples to be an interleaved set of I and
 * Q samples where the start of the block is an I sample.
 *
 * Parameters:
 * p_Cplx - Pointer to a block of interleaved (I/Q) complex samples.
 *  p_CosTable - Pointer to a 2^w_Nu point cosine table
 *  p_BitReverse - Pointer to a 2^7 point bit reverse table
 * w_Nu - Power of two corresponding to the number of points in the FFT
 *
 * Return value:  
 * 0 if successful, 0xFFFF if unsuccessful
 *
 ******************************************************************************
*/
uint16 wpc_rtte_fft( CplxS16 *p_Cplx, const int16 *p_CosTable, const uint16 *p_BitReverse, uint16 w_Nu )
{
uint16 w_TwiddleMask;
uint16 w_FpAdjust;
uint32 q_N, q_N2, q_Nu1;
uint32 q_I, q_L, q_K, q_P;
int32 l_C, l_S;
int32 l_TReal, l_TImag;
CplxS16 *p_C, *p_D;
uint32 q_Max;
uint32 q_ThisPower;

  if( w_Nu > FFT_MAX_NU )
    return( 0xffff );

  q_N           = 1 << w_Nu;   
  /*lint -e{734} : Loss of precision (assignment) (31 bits to 15 bits) */
  w_TwiddleMask = q_N - 1;
  w_FpAdjust    = 0;
  q_N2          = q_N >> 1;   
  q_Nu1         = w_Nu - 1;  
  q_Max         = 0;

  p_C = p_Cplx;
  
  /* Pre-scale input data to ensure that it is limited to a value of 16383 */
  for( q_L = 0; q_L < q_N; q_L++, p_C++ )
  {
     /*lint -e{732} : Loss of sign (assignment) (long to unsigned long) */
     q_ThisPower = (int32) p_C->x_I * p_C->x_I +
                   (int32) p_C->x_Q * p_C->x_Q;
   
     if( q_ThisPower > q_Max )
       q_Max = q_ThisPower;
   }    
   
  /* q_L is the computation array counter */
  for( q_L = 0; q_L < w_Nu; q_L++, q_N2 >>=1, q_Nu1-- )
  {
   if( q_Max >= (32768*32768) )
     {
    wpc_rtte_block_fp_adjust( p_Cplx, q_N, 2);
       w_FpAdjust += 2;
     }      
   else if( q_Max >= (16384*16384) )
     {
    wpc_rtte_block_fp_adjust( p_Cplx, q_N, 1);
       w_FpAdjust += 1;
     }      
       
   q_Max = 0;
 
   for( q_K = 0; q_K < q_N; q_K += q_N2 )
   {
    p_C = &p_Cplx[ q_K + q_N2 ];
    p_D = &p_Cplx[ q_K ];
 
    for( q_I = q_N2; q_I; q_I--, q_K++, p_C++, p_D++ )
    {
         /* Compute the index into the twiddle factors */
     q_P = wpc_rtte_bit_reverse( p_BitReverse, ( q_K >> q_Nu1 ) ); 
         
         /* Get the twiddle factors. Vector amplitude is 32768 */
     l_C = (int16) p_CosTable[ q_P ];
     l_S = (int16) p_CosTable[ (q_P - (1 << w_Nu)/4) & w_TwiddleMask ];
 
     /*lint -e{704} : Shift right of signed quantity (long) */
     l_TReal =  (((p_C->x_I * l_C + p_C->x_Q * l_S) >> 14) + 1) >> 1;
     /*lint -e{734} : Loss of precision (assignment) (31 bits to 15 bits) */
     /*lint -e{704} : Shift right of signed quantity (long) */
     l_TImag =  (((p_C->x_Q * l_C - p_C->x_I * l_S) >> 14) + 1) >> 1;
 
     /*lint -e{734} : Loss of precision (assignment) (31 bits to 15 bits) */
     p_C->x_I = p_D->x_I - l_TReal;
         /*lint -e{732} : Loss of sign (assignment) (int to unsigned long) */
         q_ThisPower = p_C->x_I * p_C->x_I;
         
     /*lint -e{734} : Loss of precision (assignment) (31 bits to 15 bits) */
     p_C->x_Q = p_D->x_Q - l_TImag;
         /*lint -e{737} : Loss of sign in promotion from int to unsigned long */
         q_ThisPower += p_C->x_Q * p_C->x_Q;
         
         if( q_ThisPower > q_Max )
           q_Max = q_ThisPower;
         
     /*lint -e{734} : Loss of precision (assignment) (31 bits to 15 bits) */
     p_D->x_I += l_TReal;
     /*lint -e{732} : Loss of sign (assignment) (int to unsigned long) */
         q_ThisPower = p_D->x_I * p_D->x_I;
         
     /*lint -e{734} : Loss of precision (assignment) (31 bits to 15 bits) */
     p_D->x_Q += l_TImag;
         /*lint -e{737} : Loss of sign in promotion from int to unsigned long */
         q_ThisPower += p_D->x_Q * p_D->x_Q;
         
         if( q_ThisPower > q_Max )
           q_Max = q_ThisPower;
 
     /* Need to install block floating point estimator here */
    }
   }
 
  }
 
  for( q_K = 0; q_K < q_N;q_K ++ )
  {
   q_I = wpc_rtte_bit_reverse( p_BitReverse, q_K ); 
 
   if( q_I > q_K )
   {
   CplxS16 z_Cplx;
 
    p_C = &p_Cplx[ q_I ];
    p_D = &p_Cplx[ q_K ];
 
    z_Cplx = *p_D;
    *p_D = *p_C;
    *p_C = z_Cplx;
   }
  }
  return( w_FpAdjust );
}


/*
 ******************************************************************************
 * wpc_bit_reverse
 *
 * Function description:
 *
 * This function uses the bit reverse table generated by wpc_rtte_init_fft. This table consists
 * of 128 entries of 7 bits each. If the value is 7 bits or less, then its reversal
 * is simply looked up in the bit reverse table. If it is more than 7 bits, then the 
 * top N-7 bits are looked up first and then OR'd with the lookup of the bottom 7 bits.
 * If N is less than 14, then the application needs to shift the result to the right 
 * 14 - N places.
 *
 * Parameters:
 * p_BitReverse - Pointer to bit reversal table
 *  q_X - Value to reverse
 *
 * Return value:  
 *  Bit reversed version of input 
 *
 ******************************************************************************
*/

uint32 wpc_rtte_bit_reverse( const uint16 *p_BitReverse, uint32 q_X )
{
 return ( p_BitReverse[ q_X ] );
}

/*
 ******************************************************************************
 * wpc_rtte_block_fp_adjust 
 *
 * Function description:
 * wpc_rtte_block_fp_adjust operates on a block of Complex int16 values and scales them
 * all by the specified right shift.
 *
 * Parameters:
 * p_Cplx - Pointer to a structure containing a complex int16 value.
 * q_N - Number of Complex int16 values in the block
 * q_Shift - Number of right shifts to perform
 *
 * Return value:  
 *  None
 *
 ******************************************************************************
*/
void wpc_rtte_block_fp_adjust( CplxS16 *p_Cplx, uint32 q_N, uint32 q_Shift )
{
 while( q_N-- )
 {
  /*lint -e{702} : Shift right of signed quantity (int) */
  p_Cplx->x_I >>= q_Shift;
  /*lint -e{702} : Shift right of signed quantity (int) */
  p_Cplx->x_Q >>= q_Shift;
  p_Cplx++;
 }
}

void wpc_init_rtte()
{
    int16_t w_Nu = 7;
    wpc_rtte_init_fft(ptwiddle, pbitRev, w_Nu);

}
