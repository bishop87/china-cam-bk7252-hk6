/* Europe/Rome modern EU rules (1996 onward), conversion on each clock update.
 * No persistent state, no network access, no dependence on vendor localtime.
 * Camera uses signed 32-bit time_t: preserve zero/failure and out-of-range input.
 */
typedef unsigned int u32;
static int leap(u32 year) { return !(year%4) && (year%100 || !(year%400)); }
u32 hk6_rome(u32 utc) {
    u32 days, rem, year=1970, jan=0, n, march, october, start, end;
    if (utc<820454400U || utc>2147476447U) return utc;
    days=utc/86400U; rem=utc%86400U;
    for (;;) {
        n=365U+leap(year);
        if (days<jan+n) break;
        jan+=n; ++year;
    }
    /* Epoch weekday: Thursday=4, Sunday=0. Last Sunday in March/October. */
    march=jan+89U+leap(year);
    october=jan+303U+leap(year);
    start=march-(march+4U)%7U;
    end=october-(october+4U)%7U;
    return utc + ((days>start || (days==start && rem>=3600U)) &&
                  (days<end || (days==end && rem<3600U)) ? 7200U : 3600U);
}
