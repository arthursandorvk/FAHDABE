from lthash import LtHash
import sys
import ast # to process the LThash digest given as input as a string
import re


print("Argument List:", str(sys.argv)) 


n = int(sys.argv[1]) # must be


# the degree of the lattice
d = int(sys.argv[2]) # must be int


# the first input element (which corresponds to the digest of epsilon)
input1 = sys.argv[3]

print("input1 is ", input1);


# the second input element
input2 = sys.argv[0]

print("input2 is ", input2);


# the determinant of the lattice matrix
	
def main(n, m, input1, input2):
	# All data inputs have to be sets
	
	#--------------------------------------------------------------------------------------------	
	# Because C does not support Sets natively, we consider inputs of the functions to be strings
	# then we add each input to a set before processing such input further
	#set_input1 = {input1}
	#
	#set_input1 = set(set_input1)
	#--------------------------------------------------------------------------------------------
	#lthash1.eval(input1)
	#lthash1.eval(set_input1)
	#--------------------------------------------------------------------------------------------
	# we set the digest of lthash1
	#lthash1.eval(input1)

	# we define a lthash1 object to get the string digest in input1
	lthash4 = LtHash(n,d)


	
	# we need to set the digest of lthash4 to be input1
	# we use ast to recover the list (hash digest is a list)
	epsilon_digest = ast.literal_eval(input1) # the hidden version of epsilon is already represented as a string expression of a vector 


	# we set the lthash3 digest value
	lthash4.digest = epsilon_digest



	#--------------------------------------------------------------------------------------------	
	# Because C does not support Sets natively, we consider inputs of the functions to be strings
	# then we add each input to a set before processing such input further
	set_input2 = {input2}
	#
	set_input2 = set(set_input2)
	
	# All our inputs are turned to sets right away before computing the LThash
	lthash4.add_data(set_input2) #view the code of add_data in lthash.py	

	#-------------------------------------------------------------------
	# We Work the output
	#-------------------------------------------------------------------
	
	output = lthash4.digest
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
	
	output=f"{left_brackect}{output}{right_bracket}"

	# we process the output before outputting the result
	output = output.strip()#.encode()

	#-------------------------------------------------------------------

	# we return the output
	print(output)

	


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

# we lauch the main code
main(n,d, input1, input2)
