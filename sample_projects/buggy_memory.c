/* Demo file with a deliberate memory bug, for defensive review only. */
#include <stdlib.h>

int *make_array(int n) {
    int *arr = malloc(n * sizeof(int));
    for (int i = 0; i <= n; i++) { /* off-by-one: writes one element past the end */
        arr[i] = i;
    }
    return arr; /* also never freed by caller in this demo */
}

int main(void) {
    int *a = make_array(10);
    return a[0];
}
