from lthash import LtHash
import sys

#the dimension of the lattice
n = int(sys.argv[1]) # must be

# the degree of the lattice
d = int(sys.argv[2]) # must be int

# the first input element
input1 = sys.argv[3]

# the second input element
input2 = sys.argv[4]

# the determinant of the lattice matrix
	 

def main(n, d, input1, input2):
	#-------------------------------------------------------------------------
	# All data inputs have to be sets
	# for consistency, we will format all our inputs to be sets due to different results obtained
	'''
	python3 skyfall-lthash-compute.py 8 10 'Apple'
	[995, 1019, 579, 942, 438, 793, 957, 1011]

	summer@summerthinkpad-x240:~/skyfall-python$ python3 skyfall-lthash-compute.py 8 10 {'Apple'}
	[760, 407, 374, 521, 634, 871, 61, 421]

	summer@summerthinkpad-x240:~/skyfall-python$ python3 skyfall-lthash-compute.py 8 10 {"Apple"}
	[760, 407, 374, 521, 634, 871, 61, 421]

	summer@summerthinkpad-x240:~/skyfall-python$ python3 skyfall-lthash-compute.py 8 10 Apple
	[995, 1019, 579, 942, 438, 793, 957, 1011]

	'''
	
	# Hash object
	lthash1 = LtHash(n,d)
	#--------------------------------------------------------------------------------------------	
	# Because C does not support Sets natively, we consider inputs of the functions to be strings
	# then we add each input to a set before processing such input further
	# set_input1 = {input1}
	
	set_input1 = {input1}
	lthash1.eval({input1})
	#--------------------------------------------------------------------------------------------
	
	#lthash1.eval(set_input1) 
	#-------------------------------------------------------------------------------------------

	# Hash object of the data to be added
	lthash2 = LtHash(n,d)
	#--------------------------------------------------------------------------------------------	
	# Because C does not support Sets natively, we consider inputs of the functions to be strings
	# then we add each input to a set before processing such input further
	# set_input2 = {input2}
	#
	set_input2 = {input2}
	lthash2.eval({input2})
	#--------------------------------------------------------------------------------------------
	
	#lthash2.eval(set_input2) 
	#--------------------------------------------------------------------------------------------


	# Hash of the union of the data
	lthash3 = LtHash(n,d)
	#
	#lthash3.eval(input1.union(input2))
	lthash3.eval(set_input1.union(set_input2))
	

	# Is the hash of m1+m1add different from Hash(m1)+Hash(m1add)?
	lthash1.add(lthash2)

	#print ("lthash of input1 + input2: ", input1, " and ", input2, " is ", lthash1.digest)

	#print ("lthash of set(input1) + set(input2): ", set({input1}), " and ", set({input2}), " is ", lthash3.digest)
	
	if lthash3.digest != lthash1.digest:
		print("None");		
		#return None
	else:
		#------------------------------------------
		# We precess the output of the data
		#------------------------------------------
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

		#------------------------------------------

		print(output)

		#print(str(lthash3.digest).strip());
		#binary_string = ""
		#
		#print("the output size in terms of bits is", math.log2(n*(n+d-1))) 
		#for value in lthash3.digest:
		#	binary_string += f"{value:016b}" #each integer will be converted into a x-bit binary array
		#print(" the binary string value is", binary_string, "and its length is ", len(binary_string), "bits")
		
		#	
		# return lthash1.digest
		# return binary_string
		#print(binary_string)
		
		#return lthash3.digest




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
main(n, d, input1, input2);
