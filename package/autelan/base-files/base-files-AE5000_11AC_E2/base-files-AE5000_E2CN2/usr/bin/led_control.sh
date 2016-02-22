#!/bin/sh

delay=$3
delaylen=${#delay}
print_debug()
{
        echo "Optionis:"
	echo "		green on                   	light green_led"	
	echo "		blue on                    	light blue_led"	
	echo "		green blink      <frequency>  	blink green_led"	
	echo "		blue_red blink   <frequency>    blink blue_led and red_led"	
	echo "		blue_red off        	        off blue_led and red_led"
	echo "		red_green blink        	        blink red_led and green_led"
	echo "		red_green off        	        off red_led and green_led"
	echo "		blue_green blink        	blink blue_led and green_led"
	echo "		blue_green off        	        off blue_led and green_led"
	echo "		red_blue_green blink        	blink red_led and blue_led and green_led"
	echo "		red_blue_green off        	off red_led andblue_led and green_led"
	echo "		fault_status on  <frequency>    blink blue_led and red_led"	
	echo "		fault_status off        	off blue_led and red_led"	
	echo "	        detect on                  	detect led on"
	echo "	        detect off                 	detec led off"
}

green_led_blink()
{
        local detect=`uci get system.led_blue.detect 2>/dev/null` 
	local upgrade=`uci get system.led_blue.upgrade 2>/dev/null` 
        local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$detect" = "1" ];then
		return
	fi
	if [ "$upgrade" = "1" ];then
		return
	fi
	if [ "$fault" = "1" ];then
		return
	fi
        local greensection=`uci get system.led_green 2>/dev/null`  
        local sectionlen=${#greensection}                                                

        if [ $sectionlen == 0 ];then
		uci set system.led_green=led
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci set system.led_green.name="LED_GREEN"
	uci set system.led_green.trigger="timer"	
	uci set system.led_green.delayon=$delay 2>/dev/null
	uci set system.led_green.delayoff=$delay 2>/dev/null
	uci set system.led_green.sysfs="ae5000_11ac_e2:green:status"
	uci delete system.led_red 2>/dev/null
	uci delete system.led_blue 2>/dev/null
	uci commit system
	/etc/init.d/led reload
}

blue_red_led_blink()
{
        local bluesection=`uci get system.led_blue 2>/dev/null`  
        local bluesectionlen=${#bluesection}                                                
        local redsection=`uci get system.led_red 2>/dev/null`  
        local redsectionlen=${#redsection}                                                
	local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi 

        if [ $bluesectionlen == 0 ];then
		uci set system.led_blue=led
	fi
        if [ $redsectionlen == 0 ];then
		uci set system.led_red=led
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci set system.led_blue.name="LED_BLUE"
	uci set system.led_blue.trigger="poll"	
	uci set system.led_blue.upgrade=1
	uci set system.led_blue.frequency=$delay
	uci set system.led_blue.sysfs="ae5000_11ac_e2:blue:status"
	uci set system.led_red.name="LED_RED"
	uci set system.led_red.trigger="poll"	
	uci set system.led_red.frequency=$delay
	uci set system.led_red.sysfs="ae5000_11ac_e2:red:status"
	uci delete system.led_green 2>/dev/null
	uci commit system
	/etc/init.d/led reload
}

blue_red_led_off()
{
	local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi 
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci delete system.led_green 2>/dev/null
	uci delete system.led_red 2>/dev/null
	uci delete system.led_blue 2>/dev/null
	uci commit system
	/etc/init.d/led reload
}

red_blue_green_led_blink()
{
        local bluesection=`uci get system.led_blue 2>/dev/null`  
        local bluesectionlen=${#bluesection}                                                
        local redsection=`uci get system.led_red 2>/dev/null`  
        local redsectionlen=${#redsection}                                                
        local greensection=`uci get system.led_green 2>/dev/null`  
        local greensectionlen=${#greensection}                                                
	local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi 

        if [ $bluesectionlen == 0 ];then
		uci set system.led_blue=led
	fi
        if [ $redsectionlen == 0 ];then
		uci set system.led_red=led
	fi
        if [ $greensectionlen == 0 ];then
		uci set system.led_green=led
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci set system.led_blue.name="LED_BLUE"
	uci set system.led_blue.trigger="poll"	
	uci set system.led_blue.upgrade=1
	uci set system.led_blue.frequency=$delay
	uci set system.led_blue.sysfs="ae5000_11ac_e2:blue:status"
	uci set system.led_red.name="LED_RED"
	uci set system.led_red.trigger="poll"	
	uci set system.led_red.frequency=$delay
	uci set system.led_red.sysfs="ae5000_11ac_e2:red:status"
	uci set system.led_green.name="LED_GREEN"
	uci set system.led_green.trigger="poll"	
	uci set system.led_green.frequency=$delay
	uci set system.led_green.sysfs="ae5000_11ac_e2:green:status"
	uci commit system
	/etc/init.d/led reload
}

red_blue_green_led_off()
{
	local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi 
	uci delete system.led_green 2>/dev/null
	uci delete system.led_red 2>/dev/null
	uci delete system.led_blue 2>/dev/null
	uci commit system
	/etc/init.d/led reload
}

red_green_led_blink()
{
        local redsection=`uci get system.led_red 2>/dev/null`  
        local redsectionlen=${#redsection}                                                
        local greensection=`uci get system.led_green 2>/dev/null`  
        local greensectionlen=${#greensection}                                                
	local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi 

        if [ $redsectionlen == 0 ];then
		uci set system.led_red=led
	fi
        if [ $greensectionlen == 0 ];then
		uci set system.led_green=led
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci set system.led_red.name="LED_RED"
	uci set system.led_red.trigger="poll"	
	uci set system.led_red.upgrade=1
	uci set system.led_red.frequency=$delay
	uci set system.led_red.sysfs="ae5000_11ac_e2:red:status"
	uci set system.led_green.name="LED_GREEN"
	uci set system.led_green.trigger="poll"	
	uci set system.led_green.frequency=$delay
	uci set system.led_green.sysfs="ae5000_11ac_e2:green:status"
	uci delete system.led_blue 2>/dev/null
	uci commit system
	/etc/init.d/led reload
}
red_green_led_off()
{
	local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi 
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci delete system.led_green 2>/dev/null
	uci delete system.led_red 2>/dev/null
	uci delete system.led_blue 2>/dev/null
	uci commit system
	/etc/init.d/led reload
}
blue_green_led_blink()
{
        local bluesection=`uci get system.led_blue 2>/dev/null`  
        local bluesectionlen=${#bluesection}                                                
        local greensection=`uci get system.led_green 2>/dev/null`  
        local greensectionlen=${#greensection}                                                
	local fault=`uci get system.led_blue.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi 

        if [ $bluesectionlen == 0 ];then
		uci set system.led_blue=led
	fi
        if [ $greensectionlen == 0 ];then
		uci set system.led_green=led
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci set system.led_blue.name="LED_BLUE"
	uci set system.led_blue.trigger="poll"	
	uci set system.led_blue.upgrade=1
	uci set system.led_blue.frequency=$delay
	uci set system.led_blue.sysfs="ae5000_11ac_e2:blue:status"
	uci set system.led_green.name="LED_RED"
	uci set system.led_green.trigger="poll"	
	uci set system.led_green.frequency=$delay
	uci set system.led_green.sysfs="ae5000_11ac_e2:green:status"
	uci delete system.led_red 2>/dev/null
	uci commit system
	/etc/init.d/led reload
}
blue_green_led_off()
{
	local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi 
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci delete system.led_green 2>/dev/null
	uci delete system.led_red 2>/dev/null
	uci delete system.led_blue 2>/dev/null
	uci commit system
	/etc/init.d/led reload
}

fault_status_on()
{
        local redsection=`uci get system.led_red 2>/dev/null`  
        local redsectionlen=${#redsection}                                                

        if [ $redsectionlen == 0 ];then
		uci set system.led_red=led
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci set system.led_red.name="LED_RED"
	uci set system.led_red.fault=1
	uci set system.led_red.trigger="timer"	
	uci set system.led_red.delayon=$delay
	uci set system.led_red.delayoff=$delay
	uci set system.led_red.sysfs="ae5000_11ac_e2:red:status"
	uci delete system.led_green 2>/dev/null
	uci delete system.led_blue 2>/dev/null
	uci commit system
	/etc/init.d/led reload
}

fault_status_off()
{	
	local fault=`uci get system.led_red.fault 2>/dev/null`
	if [ "$fault" != "1" ];then
		return
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci delete system.led_red 2>/dev/null
	uci commit system

	/etc/init.d/led reload
}

green_led_on()
{
        local detect=`uci get system.led_blue.detect 2>/dev/null`  
        local upgrade=`uci get system.led_blue.upgrade 2>/dev/null`
	local fault=`uci get system.led_red.fault 2>/dev/null`    
	if [ "$detect" = "1" ];then
		return
	fi
	if [ "$upgrade" = "1" ];then
		return
	fi
	if [ "$fault" = "1" ];then
		return
	fi
        local greensection=`uci get system.led_green 2>/dev/null`  
        local sectionlen=${#greensection}                                                

        if [ $sectionlen == 0 ];then
		uci set system.led_green=led
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci set system.led_green.name="LED_GREEN"
	uci set system.led_green.trigger="default-on"	
	uci set system.led_green.sysfs="ae5000_11ac_e2:green:status"
	uci delete system.led_red 2>/dev/null
	uci delete system.led_blue 2>/dev/null
	uci commit system
	/etc/init.d/led reload
		
}

blue_led_on()
{
        local detect=`uci get system.led_blue.detect 2>/dev/null`  
        local upgrade=`uci get system.led_blue.upgrade 2>/dev/null` 
        local fault=`uci get system.led_red.fault 2>/dev/null`   
	if [ "$detect" = "1" ];then
		return
	fi
	if [ "$upgrade" = "1" ];then
		return
	fi
	if [ "$fault" = "1" ];then
		return
	fi
        local bluesection=`uci get system.led_blue 2>/dev/null`  
        local sectionlen=${#bluesection}                                                

        if [ $sectionlen == 0 ];then
		uci set system.led_blue=led
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci set system.led_blue.name="LED_BLUE"
	uci set system.led_blue.trigger="default-on"	
	uci set system.led_blue.sysfs="ae5000_11ac_e2:blue:status"
	uci delete system.led_red 2>/dev/null
	uci delete system.led_green 2>/dev/null
	uci commit system
	/etc/init.d/led reload
		
}

blue_led_blink()
{
        local bluesection=`uci get system.led_blue 2>/dev/null`  
        local upgrade=`uci get system.led_blue.upgrade 2>/dev/null`  
	local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi
	if [ "$upgrade" = "1" ];then
		return
	fi
        local sectionlen=${#bluesection}                                                

        if [ $sectionlen == 0 ];then
		uci set system.led_blue=led
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci set system.led_blue.name="LED_BLUE"
	uci set system.led_blue.trigger="timer"	
	uci set system.led_blue.delayon=200	
	uci set system.led_blue.delayoff=200	
	uci set system.led_blue.sysfs="ae5000_11ac_e2:blue:status"
	uci set system.led_blue.detect=1
	uci delete system.led_red 2>/dev/null
	uci delete system.led_green 2>/dev/null
	uci commit system
	/etc/init.d/led reload
		
}

blue_led_off()
{
        local upgrade=`uci get system.led_blue.upgrade 2>/dev/null` 
	local fault=`uci get system.led_red.fault 2>/dev/null`  
	if [ "$fault" = "1" ];then
		return
	fi 
	if [ "$upgrade" = "1" ];then
		return
	fi
	echo 0 > /sys/class/leds/ae5000_11ac_e2:red:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:blue:status/brightness
	echo 0 > /sys/class/leds/ae5000_11ac_e2:green:status/brightness
	uci delete system.led_red 2>/dev/null
	uci delete system.led_green 2>/dev/null
	uci delete system.led_blue 2>/dev/null
	uci commit system
	ubus call ap-monitor led_control		
	/etc/init.d/led reload
}

if [ "$1" = "green" ];then
	if [ "$2" = "on" ];then
		green_led_on
	elif [ $delaylen = 0 ]; then
		print_debug
	elif [ "$2" = "blink" ];then
		green_led_blink
	else
		print_debug
	fi
elif [ "$1" = "fault_status" ];then
	if [ "$2" = "on" ];then
		fault_status_on	
	elif [ "$2" = "off" ]; then
		fault_status_off
	else
		print_debug
	fi
elif [ "$1" = "blue_red" ];then
	if [ "$2" = "blink" ];then
		blue_red_led_blink
	elif [ "$2" = "off" ]; then
		blue_red_led_off
	else
		print_debug
	fi
elif [ "$1" = "red_green" ];then
	if [ "$2" = "blink" ];then
		red_green_led_blink
	elif [ "$2" = "off" ]; then
		red_green_led_off
	else
		print_debug
	fi
elif [ "$1" = "blue_green" ];then
	if [ "$2" = "blink" ];then
		blue_green_led_blink
	elif [ "$2" = "off" ]; then
		blue_green_led_off
	else
		print_debug
	fi
elif [ "$1" = "red_blue_green" ];then
	if [ "$2" = "blink" ];then
		red_blue_green_led_blink
	elif [ "$2" = "off" ]; then
		red_blue_green_led_off
	else
		print_debug
	fi
elif [ "$1" = "blue" ];then
	if [ "$2" = "on" ];then
		blue_led_on
	else
		print_debug
	fi
elif [ "$1" = "detect" ];then
	if [ "$2" = "on" ];then
		blue_led_blink
	elif [ "$2" = "off" ];then
		blue_led_off
	else
		print_debug
	fi
else
	print_debug
fi
