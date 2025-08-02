class ECCPoint:
    def __init__(self, x, y, a, b):
        self.x = x
        self.y = y
        self.a = a
        self.b = b

    def is_valid_curve(self):
        # Check if 4a³ + 27b² ≠ 0 (mod p)
        return (4 * (self.a ** 3) + 27 * (self.b ** 2)) % p != 0

    def is_on_curve(self):
        # Check if y² ≡ x³ + ax + b (mod p)
        return (self.y ** 2) % p == (self.x ** 3 + self.a * self.x + self.b) % p

    def add_points(self, p1, p2):
        if p1.x == p2.x and p1.y == p2.y:
            # Point doubling
            slope = (3 * (p1.x ** 2) + self.a) / (2 * p1.y)
        else:
            # Point addition
            slope = (p2.y - p1.y) / (p2.x - p1.x)
        x3 = (slope ** 2) - p1.x - p2.x
        y3 = slope * (p1.x - x3) - p1.y
        return ECCPoint(x3, y3, self.a, self.b)

    def scalar_multiply(self, point, scalar):
        result = ECCPoint(point.x, point.y, self.a, self.b)
        for _ in range(scalar - 1):
            result = self.add_points(result, point)
        return result


def DH_key_exchange(base_point, private_key_A, private_key_B):
    public_key_A = base_point.scalar_multiply(base_point, private_key_A)
    public_key_B = base_point.scalar_multiply(base_point, private_key_B)
    shared_secret_A = public_key_B.scalar_multiply(public_key_B, private_key_A)
    shared_secret_B = public_key_A.scalar_multiply(public_key_A, private_key_B)
    return shared_secret_A, shared_secret_B


def encrypt(message, public_key):
    cipher_point = public_key.scalar_multiply(public_key, message)
    return cipher_point


def decrypt(cipher_point, private_key):
    plain_text = cipher_point.scalar_multiply(cipher_point, private_key)
    return plain_text


def print_menu():
    print("\nMenu:")
    print("1. Verify if Elliptic Curve is valid")
    print("2. Verify if a Point is on the Curve")
    print("3. Perform ECC-based Diffie-Hellman Key Exchange")
    print("4. Perform Public Key Based Encryption")
    print("5. Exit")


if __name__ == "__main__":
    # Define parameters
    p = 17
    a = 2
    b = 2
    base_point = ECCPoint(5, 1, a, b)

    while True:
        print_menu()
        choice = input("Enter your choice (1-5): ")

        if choice == "1":
            curve = ECCPoint(0, 0, a, b)
            is_valid_curve = curve.is_valid_curve()
            print("Is the curve valid?", is_valid_curve)
        elif choice == "2":
            point = ECCPoint(5, 1, a, b)
            is_on_curve = point.is_on_curve()
            print("Is the point on the curve?", is_on_curve)
        elif choice == "3":
            private_key_A = int(input("Enter private key for party A: "))
            private_key_B = int(input("Enter private key for party B: "))
            shared_secret_A, shared_secret_B = DH_key_exchange(base_point, private_key_A, private_key_B)
            print("Shared Secret A:", shared_secret_A.x)
            print("Shared Secret B:", shared_secret_B.x)
        elif choice == "4":
            message = int(input("Enter message to encrypt: "))
            cipher_text = encrypt(message, base_point)
            print("Cipher Text:", cipher_text.x)
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 5.")