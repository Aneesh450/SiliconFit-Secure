"""A small, clean sample project used to demonstrate SiliconFit Secure on a safe file."""


def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


if __name__ == "__main__":
    print("Fibonacci(10):", fibonacci(10))
    print("Primes under 30:", [n for n in range(30) if is_prime(n)])
