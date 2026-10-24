.syntax unified
.cpu arm968e-s
.thumb
.section .text.entry,"ax",%progbits
.global hk6_app_clock
.type hk6_app_clock,%function
.thumb_func
hk6_app_clock:
    /* At 0x19b50: r0=cJSON time node, caller SP aligned. Original
     * sequence writes time-tz to caller SP+12 and passes its address to localtime.
     * Ignore the app's DST-blind tz; convert the UTC field using Europe/Rome.
     */
    push {r1-r3,lr}
    ldr r0,[r0,#20]
    bl hk6_rome
    str r0,[sp,#28]
    add r0,sp,#28
    pop {r1-r3,pc}
.size hk6_app_clock,.-hk6_app_clock
