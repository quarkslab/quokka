/* Test binary for IDA apply-back signature verification.
 *
 * Compile: gcc -o sig_test sig_test_source.c -O0 -no-pie -fno-stack-protector
 *
 * Each function has a clear, unambiguous prototype that IDA will faithfully
 * reproduce in its type system.  The printf calls ensure the functions are
 * non-trivial so IDA/Hex-Rays will decompile them with visible parameters.
 */

#include <stdio.h>

__attribute__((noinline))
int add_two(int x, int y) {
    printf("sum: %d\n", x + y);
    return x + y;
}

__attribute__((noinline))
long compute_three(long a, long b, long c) {
    long result = (a * b) + c;
    printf("result: %ld\n", result);
    return result;
}

__attribute__((noinline))
int use_char_ptr(int count, char *msg) {
    int i;
    for (i = 0; i < count; i++)
        printf("%s\n", msg);
    return count;
}

int main(int argc, char **argv) {
    int r1 = add_two(10, 20);
    long r2 = compute_three(30, 40, 50);
    int r3 = use_char_ptr(3, "hello");
    printf("results: %d, %ld, %d\n", r1, r2, r3);
    return 0;
}
