from LThash.lthash import LtHash

# Some parameters for our tests.
n = 8
d = 10  # q = 2^d = 1024
print('n = ', n, ', d = ', d)

# Example data
m1 = {'Entry 1', 'Entry 2'}
print('m1 = ', m1)
# new object
lthash1 = LtHash(n, d)
# evaluating: populating self.digest with the output of the hash function
lthash1.eval(m1)
print('H(m1) = ', lthash1.digest)

i = input("Press Enter to continue: ")

# Let us first see how adding data works:
m2 = 'Entry 3'
print('m2 = ', m2)
lthash1.add_data(m2)
print('H(m1) + H(m2) = ', lthash1.digest)

i = input("Press Enter to continue: ")

# Does it yield what it should?
m12 = {'Entry 1', 'Entry 2', 'Entry 3'}
print('m1 u {m2} = ', m12)
lthash12 = LtHash(n, d, m12)
print('H(m1 u {m2}) = ', lthash12.digest)
print('It is ', lthash1.digest == lthash12.digest, ' that set homomorphism works: H(m1 u {m2}) = H(m1) + H(m2)!')

i = input("Press Enter to continue: ")

# We can also remove elements:
lthash1.rem_data(m2)
lthash_test = LtHash(n, d, m1)
print('It is ', lthash1.digest == lthash_test.digest, ' that H(m1 u m2) - H(m2) = H(m1)')

i = input("Press Enter to continue: ")

# The above example can be run automatically using the tests:
# test_hom(n, d, m12, {'Entry 4'}, {m2})
