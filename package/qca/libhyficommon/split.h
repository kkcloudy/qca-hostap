/*
 *  Copyright (c) 2010 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#ifndef split__h /*once only*/
#define split__h




/*-F- splitSort -- sort the results of split (less)
 */
extern
void splitSort(
        int MaxWords,
        int WordBufSize,
        char Words[MaxWords][WordBufSize])
;


/*-F- splitByToken -- split string into "words" separated by Token given, such
 *       as ',', ' ' etc.
 *
 *       Returns words as null-terminated strings in Dst where the words
 *       are spaced apart at WordBufSize bytes apart.
 *       Return value is number of words extracted.
 *       Buffer overflow causes a return value of -1.
 *
 *       This is useful where the client code declares memory like:
 *               char XXBuf[MaxWords][WordBufSize+1]
 *       and calls splitByToken as:
 *               int NWords = splitByToken(
 *                       XXSrc,
 *                       sizeof(XXBuf)/sizeof(XXBuf[0]),
 *                       sizeof(XXBuf[0]),
 *                       XXBuf,
 *                       Token);
 *       and can then access the individual strings as:
 *                       XXBuf[i]
 */
extern
int splitByToken(
    const char *Src,    /* source string */
    int MaxWords,       /* max. no. of strings extracted */
    int WordBufSize,    /* spacing between strings */
    char *Dst,          /* logically 2D but physically flat (1D) allocation */
    const char Token)
;


/*-F- splitLineByMultiSpace -- split line in config-file, such as pppoeconnmap,
 *       which is seperated by multi-space, into "words", and trim the
 *       left/right space of current line
 *
 *       Returns words as null-terminated strings in Dst where the words
 *       are spaced apart at WordBufSize bytes apart.
 *       Return value is number of words extracted.
 *       Buffer overflow causes a return value of -1.
 *
 *       This is useful where the client code declares memory like:
 *               char XXBuf[MaxWords][WordBufSize+1]
 *       and calls splitLineByMultiSpace as:
 *               int NWords = splitLineByMultiSpace(
 *                       XXSrc,
 *                       sizeof(XXBuf)/sizeof(XXBuf[0]),
 *                       sizeof(XXBuf[0]),
 *                       XXBuf);
 *       and can then access the individual strings as:
 *                       XXBuf[i]
 */

extern
int splitLineByMultiSpace(
        const char* Src,
        int MaxWords, 
        int WordBufSize,
        char *Dst /* logically 2D but physically flat (1D) allocation */)
;
                              /*-;-*/



#endif










