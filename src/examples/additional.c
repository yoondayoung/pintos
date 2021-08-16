/* additional.c

   comupute fibonacci number of num1,
   and find the max number among num1, num2, num3, num4. */

#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main(int argc, char* argv[])
{
    int res_fibo, res_max4;
    int num1, num2, num3, num4;

    if (argc != 5)
    {
        printf("usage: additional nun1 num2 num3 num4\n");
        return EXIT_FAILURE;
    }
    
    /* get the int value of args */
    num1 = atoi(argv[1]);
    num2 = atoi(argv[2]);
    num3 = atoi(argv[3]);
    num4 = atoi(argv[4]);

    /* calculate fibonacci number of num1 */
    res_fibo = fibonacci(num1);

    /* find the max number of num1, num2, num3, num4 */
    res_max4 = max_of_four_int(num1, num2, num3, num4);
    
    /* print the result */
    printf("%d %d\n", res_fibo, res_max4);

    return EXIT_SUCCESS;
}

