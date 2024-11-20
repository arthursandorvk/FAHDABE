from lthash import LtHash
import sys
import math
#
import json

#the dimension of the lattice
n = int(sys.argv[1]) # must be

# the degree of the lattice
d = int(sys.argv[2]) # must be int

# the first input element
input1 = sys.argv[3]

# the second input element
#input2 = sys.argv[4]

# the determinant of the lattice matrix


# to compute the LTHASH of an input1 is a char*, an array of characters or a set of characters
def main(n, d, input1):
	
	# Example data
	#input1 = {'Entry 1', 'Entry 2'}
	
	#--------------------------------------------------------------------------------------------	
	# Because C does not support Sets natively, we consider inputs of the functions to be strings
	# then we add each input to a set before processing such input further
	set_input1 = {input1}
	#
	
	# New Hash object
	lthash1 = LtHash(n,d)

	#--------------------------------------------------------------------------------------------	
	# evaluating: populating self.digest with the output of the hash function
	#lthash1.eval(input1) # view the code of eval in lthash.py
	
	lthash1.eval(set_input1)
	#--------------------------------------------------------------------------------------------
	
	# we process the output
	output = lthash1.digest
	#
	# We use map and join conjointly
	mapped_output = map(str, output)
	#
	# we convert the output into a string separated by space (space is used in ABE to separate attributes of the access policy so no space)
	output =  ",".join(mapped_output) #" ".join(str(element) for element in output )
	# we will jsonify the output content
	
	#output = json.dumps(output)
	#
	# python strings are Unicode while C strings are byte sequences
	# print(output)

	# we will insert "[" and "]" to the list so as to have a string expression of the list
	left_brackect='['
	#
	right_bracket=']'
	#
	#--------------------------------------------------------------------
	# output_list = output[:0] + left_brackect + output[0:-1] + right_bracket + output[-1:]
	#----------------------------------------------------------------------
	#
	
	output=f"{left_brackect}{output}{right_bracket}"

	# we process the output before outputting the result
	output = output.strip()#.encode()
	#
	print(output)
	#
	#print(output.encode())
	#	
	#print(str(output))
	#
	#binary_string = ""
	#
	#print("the output size in terms of bits is", math.log2(n*(n+d-1))) 
	#for value in lthash1.digest:
	#	binary_string += f"{value:016b}" #each integer will be converted into a x-bit binary array
	#print(" the binary string value is", binary_string, "and its length is ", len(binary_string), "bits")
		
	#	
	# return lthash1.digest
	# return binary_string
	#print(binary_string)

def test_hom(n, d, m1, m1add, m1rem):
	if test_rem(n,d,m1, m1rem):
		print('Method rem is not working!')
	elif test_rem_data(n,d,m1, m1rem):
		print('Method rem_data is not working!')
	elif test_add(n,d,m1, m1add):
		print('Method add is not working!')
	elif test_add_data(n,d,m1, m1add):
		print('Method add_data is not working!')
	else:
		print('Set homomorphism works!')

# we launch the main code
main(n, d, input1);
