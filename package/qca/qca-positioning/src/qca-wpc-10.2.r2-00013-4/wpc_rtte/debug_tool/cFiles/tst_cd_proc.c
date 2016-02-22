#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

u_int32_t wpc_rtte_reverse_bit(u_int32_t temp){
    u_int32_t b0, b1, b2, b3;
    b0 = (temp & 0x000000ff) >> 0;
    b1 = (temp & 0x0000ff00) >> 8;
    b2 = (temp & 0x00ff0000) >> 16;
    b3 = (temp & 0xff000000) >> 24;
    return ((b0 <<24) + (b1 <<16) + (b2 <<8) + (b3 << 0));
}


int main(int argc, char **argv)
{
    u_int16_t i =0, j = 0, k = 0;
    int16_t w_Nu = 7;
    int bitRev = 0;
    u_int32_t q_N = 1 << w_Nu;
    u_int32_t ath_me_h_in_mem[1024];
    u_int32_t ath_read[4096];
    if(argc <2 ){
        printf("Usage: \n\t %s filename \n", argv[0]);
        return -1;
    }
    if(argc >2){
        bitRev = atoi(argv[2]);
    }
    FILE *file = fopen(argv[1], "r");
    if(file == NULL) {
        printf(" Cannot open file %s \n", argv[1]);
        return -2;
    }
    FILE * file1 = fopen("cd_matlab.txt", "w");
    FILE * file2 = fopen("cd_cprogram.txt", "w");
    while(fscanf(file,"%x",&ath_read[i]) != EOF) {
        fprintf(file1, "%02x", ath_read[i]); //to print '0' value as well
        i++;
    }
    printf("Total size: %d\n", i);
    fprintf(file1, "\n");
    while(j < i){
        if(bitRev)
            ath_me_h_in_mem[k] = ath_read[j] + (ath_read[j+1] << 8)+(ath_read[j+2] << 16)+(ath_read[j+3] << 24);
        else
            ath_me_h_in_mem[k] = ath_read[j+3] + (ath_read[j+2] << 8)+(ath_read[j+1] << 16)+(ath_read[j] << 24);

        fprintf(file2,"%08x ", ath_me_h_in_mem[k]);
        j = j+4;
        k++;
    }
    fprintf(file2, "\n");
    fclose(file);
    fclose(file1);
    fclose(file2);
    return 0; 
    
}



