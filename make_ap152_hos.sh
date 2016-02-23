#!/bin/sh

OPTION=""
SYSUPG=sysupgrade
AUTE_SYSUPG=autelan-sysupgrade
FILE_PATH=package/base-files/files/sbin
TAR_LIST=""

if [ $# -ge 1 ]; then
	OPTION=$1
fi

IMG_NAME=AFi-A1.img
DESC_FILE=image-describe
VERSION_NAME=openwrt-ar71xx-generic-ap152-afi-squashfs-sysupgrade.bin
FIRMWARE_NAME=openwrt-ar71xx-generic-afi-a1-squashfs-sysupgrade.bin
VERSION="`cat image-describe | awk -F " " '/version/ {print $3}'`"

rm -rf build_dir/target-*/hos-*
rm -rf build_dir/target-mips_34kc_uClibc-0.9.33.2/linux-ar71xx_generic/base-files
rm -rf tmp

export AT_PRODUCT=AFI_A1
export AT_PLATFORM=AP152_AFI

rm -rf .config
cp AP152_AFI_A1.config  .config
make defconfig
make V=s

#cp $DESC_FILE bin/ar71xx/
cd bin/ar71xx/

rm -rf $DESC_FILE
touch $DESC_FILE

echo "config spec hardware" > $DESC_FILE && \
echo "	option hardtype		afi-a1" >> $DESC_FILE && \
echo "	option flashsize	16M"   >> $DESC_FILE && \
echo "	option flashcount	1" >> $DESC_FILE

#write spec sw info
echo "config spec software"         >> $DESC_FILE && \
echo "	option platform		newso"      >> $DESC_FILE

#get os type
echo "	option ha	single"             >> $DESC_FILE
echo "	option version	$VERSION"             >> $DESC_FILE
echo "	option md5	1"             >> $DESC_FILE

mv $VERSION_NAME $FIRMWARE_NAME

md5sum $FIRMWARE_NAME > sysupgrade.md5

TAR_LIST="$FIRMWARE_NAME $DESC_FILE sysupgrade.md5"
case $OPTION in
	-r)
	cp ../../$FILE_PATH/$AUTE_SYSUPG . 
	TAR_LIST="$TAR_LIST $AUTE_SYSUPG"
	;;
	-rr)
	cp ../../$FILE_PATH/$SYSUPG .
	TAR_LIST="$TAR_LIST $SYSUPG"
	;;
	-rrr)
	cp ../../$FILE_PATH/$AUTE_SYSUPG .
	cp ../../$FILE_PATH/$SYSUPG .
	TAR_LIST="$TAR_LIST $AUTE_SYSUPG $SYSUPG"
	;;
	*)
	;;
esac
tar zcvf $IMG_NAME $TAR_LIST
cd ..

