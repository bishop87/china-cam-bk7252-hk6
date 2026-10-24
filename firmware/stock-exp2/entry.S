.syntax unified
.cpu arm968e-s
.thumb
.section .text.entry,"ax",%progbits
.global hk6_guard_entry
.type hk6_guard_entry,%function
.thumb_func
hk6_guard_entry:
    /* Entry after original push {r4-r7,lr}; SP = caller SP - 20.
     * Replaced instructions: sub sp,#44; str r3,[sp,#20].
     * Save 20 bytes: keep C call aligned to eight bytes.
     */
    push {r0-r3,lr}
    movs r1,r2
    ldr r2,[sp,#48]  /* original seventh argument: netif */
    ldr r3,[sp,#44]  /* original sixth argument: protocol */
    bl hk6_packet_allowed
    cmp r0,#0
    beq .Ldeny
    pop {r0-r3}
    add sp,#4       /* discard injected BL return address */
    sub sp,#44
    str r3,[sp,#20]
    bl 0x72226     /* resume original function; original LR remains saved */
.Ldeny:
    add sp,#20
    movs r0,#4
    negs r0,r0     /* ERR_RTE = -4 */
    pop {r4-r7,pc}
.size hk6_guard_entry,.-hk6_guard_entry
