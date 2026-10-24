.syntax unified
.cpu arm968e-s
.thumb
.section .text.entry,"ax",%progbits
.global hk6_idle_gate
.type hk6_idle_gate,%function
.thumb_func
hk6_idle_gate:
    /* Replaces ldr r0,[pc,#408]; bl log at 0x1a72e (six bytes).
     * C calls use the original aligned stack plus 24 bytes. */
    push {r0-r4,lr}
    bl hk6_needed
    cmp r0,#0
    beq .Lidle
    ldr r0,=0x1a621
    str r0,[sp,#20]
    pop {r0-r4,pc}
.Lidle:
    ldr r0,=0xba9d5
    ldr r4,=0x5c2e9
    blx r4
    pop {r0-r4,pc}
.size hk6_idle_gate,.-hk6_idle_gate
