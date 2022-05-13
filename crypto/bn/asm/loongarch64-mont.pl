#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# ====================================================================
# Written by Song Ding <songding@loongson.cn> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# May 2022
#
# The code improve rsa *sign* benchmark ~80-130% than original and
# imporve *verify* benchmark ~70-100% than original, see table below
# for improvement coefficients.
#
# So far 'openssl speed rsa' output on 2.5GHz loongarch64
# this module is:
#                   sign    verify    sign/s verify/s
# rsa  512 bits 0.000069s 0.000006s  14408.7 170354.3
# rsa 1024 bits 0.000370s 0.000018s   2701.5  54338.6
# rsa 2048 bits 0.002465s 0.000066s    405.7  15047.2
# rsa 3072 bits 0.008264s 0.000143s    121.0   7010.2
# rsa 4096 bits 0.017271s 0.000233s     57.9   4287.6
# rsa 7680 bits 0.101818s 0.000811s      9.8   1233.4
# rsa 15360 bits 0.755714s 0.003127s      1.3    319.8
# 
# original is:
#                   sign    verify    sign/s verify/s
# rsa  512 bits 0.000161s 0.000011s   6213.1  91696.5
# rsa 1024 bits 0.000780s 0.000034s   1281.9  29607.3
# rsa 2048 bits 0.004861s 0.000117s    205.7   8576.5
# rsa 3072 bits 0.015764s 0.000277s     63.4   3607.2
# rsa 4096 bits 0.031281s 0.000422s     32.0   2367.0
# rsa 7680 bits 0.207959s 0.001646s      4.8    607.7
# rsa 15360 bits 1.524286s 0.006378s      0.7    156.8
#
#  ---------------------------------------------------------
#  | rsa    | this/original(sign) |  this/original(verify) |
#  -------------------------------+------------------------- 
#  | 512    | +131.83%            |  +85.84%               |
#  | 1024   | +110.79%            |  +83.33%               |
#  | 2048   | +97.32%             |  +75.55%               |
#  | 3072   | +90.55%             |  +94.52%               |
#  | 4096   | +80.94%             |  +81.22%               |
#  | 7680   | +104.17%            |  +101.60%              |
#  | 15360  | +85.71%             |  +103.56%              |
#  ---------------------------------------------------------

######################################################################
# Here is register layout for LOONGARCH ABIs.
# The return value is placed in $a0.

($zero,$ra,$tp,$sp,$fp)=map("\$r$_",(0..3,22));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$r$_",(4..11));
($t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8)=map("\$r$_",(12..20));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8)=map("\$r$_",(23..31));

$PTR_ADD="addi.d";
$REG_S="st.d";
$REG_L="ld.d";
$SZREG=8;

######################################################################

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$LD="ld.d";
$ST="st.d";
$MULD="mul.d";
$MULHD="mulh.du";
$ADD="add.d";
$SUB="sub.d";
$BNSZ=8;

# int bn_mul_mont(
$rp=$a0;	# BN_ULONG *rp,
$ap=$a1;	# const BN_ULONG *ap,
$bp=$a2;	# const BN_ULONG *bp,
$np=$a3;	# const BN_ULONG *np,
$n0=$a4;	# const BN_ULONG *n0,
$num=$a5;	# int num);

$lo0=$a6;
$hi0=$a7;
$lo1=$t1;
$hi1=$t2;
$aj=$t3;
$bi=$t4;
$nj=$t5;
$tp=$t6;
$alo=$t7;
$ahi=$s0;
$nlo=$s1;
$nhi=$s2;
$tj=$s3;
$i=$s4;
$j=$s5;
$m1=$s6;

$code=<<___;
.text
.align 5
.globl bn_mul_mont
bn_mul_mont:
___
$code.=<<___;
    slti     $t8,$num,4
    li.d     $t0,0
    bnez     $t8,1f
    slti     $t8,$num,17
    bnez     $t8,bn_mul_mont_internal
1:  li.d     $a0,0
    jr       $ra

.align 5
bn_mul_mont_internal:
    addi.d   $sp,$sp,-64
    $REG_S   $fp,$sp,$SZREG*0
    $REG_S   $s0,$sp,$SZREG*1
    $REG_S   $s1,$sp,$SZREG*2
    $REG_S   $s2,$sp,$SZREG*3
    $REG_S   $s3,$sp,$SZREG*4
    $REG_S   $s4,$sp,$SZREG*5
    $REG_S   $s5,$sp,$SZREG*6
    $REG_S   $s6,$sp,$SZREG*7
___
$code.=<<___;
    move     $fp,$sp
    $LD      $n0,$n0,0
    $LD      $bi,$bp,0	# bp[0]
    $LD      $aj,$ap,0	# ap[0]
    $LD      $nj,$np,0	# np[0]
    
    $PTR_ADD $sp,$sp,-2*$BNSZ   # place for two extra words
    slli.d   $num,$num,`log($BNSZ)/log(2)`
    li.d     $t8,-4096
    $SUB     $sp,$sp,$num
    and      $sp,$sp,$t8
    
    $LD      $ahi,$ap,$BNSZ
    $LD      $nhi,$np,$BNSZ
    $MULD    $lo0,$aj,$bi
    $MULHD   $hi0,$aj,$bi
    $MULD    $m1,$lo0,$n0
    
    $MULD    $alo,$ahi,$bi
    $MULHD   $ahi,$ahi,$bi
    
    $MULD    $lo1,$nj,$m1
    $MULHD   $hi1,$nj,$m1
    $ADD     $lo1,$lo1,$lo0
    sltu     $t8,$lo1,$lo0
    $ADD     $hi1,$hi1,$t8
    $MULD    $nlo,$nhi,$m1
    $MULHD   $nhi,$nhi,$m1
    
    move     $tp,$sp
    li.d     $j,2*$BNSZ
.align 4
.L1st:
    $ADD     $aj,$ap,$j
    $ADD     $nj,$np,$j
    $LD      $aj,$aj,0
    $LD      $nj,$nj,0
    
    $ADD     $lo0,$alo,$hi0
    $ADD     $lo1,$nlo,$hi1
    sltu     $t8,$lo0,$hi0
    sltu     $t0,$lo1,$hi1
    $ADD     $hi0,$ahi,$t8
    $ADD     $hi1,$nhi,$t0
    $MULD    $alo,$aj,$bi
    $MULHD   $ahi,$aj,$bi
    
    $ADD     $lo1,$lo1,$lo0
    sltu     $t8,$lo1,$lo0
    $ADD     $hi1,$hi1,$t8
    addi.d   $j,$j,$BNSZ
    $ST      $lo1,$tp,0
    $MULD    $nlo,$nj,$m1
    $MULHD   $nhi,$nj,$m1
    
    $PTR_ADD $tp,$tp,$BNSZ
    bltu     $j,$num,.L1st
    
    $ADD     $lo0,$alo,$hi0
    sltu     $t8,$lo0,$hi0
    $ADD     $hi0,$ahi,$t8
    
    $ADD     $lo1,$nlo,$hi1
    sltu     $t0,$lo1,$hi1
    $ADD     $hi1,$nhi,$t0
    $ADD     $lo1,$lo1,$lo0
    sltu     $t8,$lo1,$lo0
    $ADD     $hi1,$hi1,$t8
    
    $ST      $lo1,$tp,0
    
    $ADD     $hi1,$hi1,$hi0
    sltu     $t8,$hi1,$hi0
    $ST      $hi1,$tp,$BNSZ
    $ST      $t8,$tp,2*$BNSZ
    
    li.d     $i,$BNSZ
.align 4
.Louter:
    $ADD     $bi,$bp,$i
    $LD      $bi,$bi,0
    $LD      $aj,$ap,0
    $LD      $ahi,$ap,$BNSZ
    $LD      $tj,$sp,0
    
    $LD      $nj,$np,0
    $LD      $nhi,$np,$BNSZ
    $MULD    $lo0,$aj,$bi
    $MULHD   $hi0,$aj,$bi
    $ADD     $lo0,$lo0,$tj
    sltu     $t8,$lo0,$tj
    $ADD     $hi0,$hi0,$t8
    $MULD    $m1,$lo0,$n0
    
    $MULD    $alo,$ahi,$bi
    $MULHD   $ahi,$ahi,$bi
    
    $MULD    $lo1,$nj,$m1
    $MULHD   $hi1,$nj,$m1
    
    $ADD     $lo1,$lo1,$lo0
    sltu     $t8,$lo1,$lo0
    $ADD     $hi1,$hi1,$t8
    $MULD    $nlo,$nhi,$m1
    $MULHD   $nhi,$nhi,$m1
    
    move     $tp,$sp
    li.d     $j,2*$BNSZ
    $LD      $tj,$tp,$BNSZ
.align 4
.Linner:
    $ADD     $aj,$ap,$j
    $ADD     $nj,$np,$j
    $LD      $aj,$aj,0
    $LD      $nj,$nj,0
    
    $ADD     $lo0,$alo,$hi0
    $ADD     $lo1,$nlo,$hi1
    sltu     $t8,$lo0,$hi0
    sltu     $t0,$lo1,$hi1
    $ADD     $hi0,$ahi,$t8
    $ADD     $hi1,$nhi,$t0
    $MULD    $alo,$aj,$bi
    $MULHD   $ahi,$aj,$bi
    
    $ADD     $lo0,$lo0,$tj
    addi.d   $j,$j,$BNSZ
    sltu     $t8,$lo0,$tj
    $ADD     $lo1,$lo1,$lo0
    $ADD     $hi0,$hi0,$t8
    sltu     $t0,$lo1,$lo0
    $LD	     $tj,$tp,2*$BNSZ
    $ADD     $hi1,$hi1,$t0
    $MULD    $nlo,$nj,$m1
    $MULHD   $nhi,$nj,$m1
    $ST      $lo1,$tp,0
    $PTR_ADD $tp,$tp,$BNSZ
    bltu     $j,$num,.Linner
    
    $ADD     $lo0,$alo,$hi0
    sltu     $t8,$lo0,$hi0
    $ADD     $hi0,$ahi,$t8
    $ADD     $lo0,$lo0,$tj
    sltu     $t0,$lo0,$tj
    $ADD     $hi0,$hi0,$t0
    
    $LD      $tj,$tp,2*$BNSZ
    $ADD     $lo1,$nlo,$hi1
    sltu     $t8,$lo1,$hi1
    $ADD     $hi1,$nhi,$t8
    $ADD     $lo1,$lo1,$lo0
    sltu     $t0,$lo1,$lo0
    $ADD     $hi1,$hi1,$t0
    $ST      $lo1,$tp,0
    
    $ADD   	 $lo1,$hi1,$hi0
    sltu     $hi1,$lo1,$hi0
    $ADD     $lo1,$lo1,$tj
    sltu     $t8,$lo1,$tj
    $ADD     $hi1,$hi1,$t8
    $ST      $lo1,$tp,$BNSZ
    $ST    	 $hi1,$tp,2*$BNSZ
    
    $PTR_ADD $i,$i,$BNSZ
    bltu     $i,$num,.Louter
    
    $ADD     $tj,$sp,$num   # &tp[num]
    move     $tp,$sp
    move     $ap,$sp
    li.d     $hi0,0   # clear borrow bit

.align 4
.Lsub:
    $LD      $lo0,$tp,0
    $LD      $lo1,$np,0
    $PTR_ADD $tp,$tp,$BNSZ
    $PTR_ADD $np,$np,$BNSZ
    $SUB     $lo1,$lo0,$lo1   # tp[i]-np[i]
    sltu     $t8,$lo0,$lo1
    $SUB     $lo0,$lo1,$hi0
    sltu     $hi0,$lo1,$lo0
    $ST      $lo0,$rp,0
    or       $hi0,$hi0,$t8
    $PTR_ADD $rp,$rp,$BNSZ
    bltu     $tp,$tj,.Lsub
    $SUB     $hi0,$hi1,$hi0	# handle upmost overflow bit
    move     $tp,$sp
    $SUB     $rp,$rp,$num   # restore rp
    nor      $hi1,$hi0,$zero
.Lcopy:
    $LD      $nj,$tp,0   # conditional move
    $LD	     $aj,$rp,0
    $ST	     $zero,$tp,0
    $PTR_ADD $tp,$tp,$BNSZ
    and	     $nj,$nj,$hi0
    and	     $aj,$aj,$hi1
    or	     $aj,$aj,$nj
    $ST	     $aj,$rp,0
    $PTR_ADD $rp,$rp,$BNSZ
    bltu     $tp,$tj,.Lcopy
    li.d     $a0,1
    li.d     $t0,1
    move     $sp,$fp
___
$code.=<<___;
    $REG_L   $fp,$sp,$SZREG*0
    $REG_L   $s0,$sp,$SZREG*1
    $REG_L   $s1,$sp,$SZREG*2
    $REG_L   $s2,$sp,$SZREG*3
    $REG_L   $s3,$sp,$SZREG*4
    $REG_L   $s4,$sp,$SZREG*5
    $REG_L   $s5,$sp,$SZREG*6
    $REG_L   $s6,$sp,$SZREG*7
    $PTR_ADD $sp,$sp,64;
    jr       $ra
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;

print $code;
close STDOUT;
