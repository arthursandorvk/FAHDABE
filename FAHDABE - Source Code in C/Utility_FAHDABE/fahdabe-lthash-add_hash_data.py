from lthash import LtHash
import sys
import ast # to process the LThash digest given as input as a string
import re

#for the shared memory object
import mmap
import os
import time
import sysv_ipc # the shared memory module

import ctypes


n = int(sys.argv[1]) # must be

# the degree of the lattice
d = int(sys.argv[2]) # must be int


# the second input element
input2 = sys.argv[3]

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



#-------------------------------------------------------------------------------
# the first input element as the string of a LThash digest
#input1 = sys.argv[3]
#input1 = list(map(int,sys.argv[1:-1]))
#input1 = " ".join(sys.argv[3:-1])
#print(f" \n \n Received string without quotes: {input1} \n \n")

#print("the list of all arguments is ", sys.argv, "with length ", len(sys.argv))
#input1_string = ast.literal_eval(input1)
#print(f"Received string with quotes: {input1_string}\n")
#-------------------------------------------------------------------------------
'''
# in case we use a structure in C, we need to define a class here that will help to retrieve data from such structure
class CStruct(ctypes.Structure):
	_fields_ = [
		("buffer", ctypes.c_char * 4096),
		("count_bytes", ctypes.c_size_t)
	]

while True:
	try:
		fd = os.open("shm5", os.O_RDWR) # we open shared memory in read-only mode
		#
		break
	except FileNotFoundError:
		print("Shared Memory object not found yet. Waiting....")
		time.sleep(1)

mm = mmap.mmap(fd, 0, prot=mmap.PROT_READ) # read-only protection

while True:
	if mm.read(4096): # we check if data is available
		input1 = mm.read(4096).decode().strip("\x00") # we remove the null bytes
		print(f"\n Received  from C--->: {input1}\n\n")
		break
	time.sleep(0.1) # we wait briefly if data is not ready

mm.close()
os.close(fd)
'''
#-----------------------------------------------------------------------
'''with open('myregion.mmap', 'r') as fd:
	with mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ) as m:
		print(m.read(100))
'''
#----------------------------------------------------------------------
'''
# we use shmat
while True:
	try:
		# we get the shared memory ID
		shared_memory = sysv_ipc.SharedMemory(key=4321, size=4096) #shmget(key=4321, size=4096, flags=0)
		break
	except sysv_ipc.ExistentialError:
		print("Shared memory object not found")
		time.sleep(1)
#
#shared_memory = sysv_ipc.shmat(segment_id, None, 0) # we attach the shared memory
#
while True:
	if b"\0" not in shared_memory.read(): # we use the nullbyte to check if data is available
		message = shared_memory.read().decode().strip()
		print("\n \n Received from C: ", message)
		break
	time.sleep(0.1) # wait briefly if data is not ready

#sysv_ipc.shmdt(shared_memory) # we detach the shared memory
#
#sysv_ipc.shmctl(segment_id, sysv_ipc.IPC_RMID, None) # WE mark the shared memory for removal

shared_memory.detach()
shared_memory.remove() # optional
'''
#-----------------------------------------------------------------------
# we open the shared memory object ( if the shared memory does not exist it will be created)
'''fd = os.open("/myregion.mmap", os.O_RDWR)

with open("/myregion.mmap", mode="r", encoding='utf-8') as fd:
	content = fd.read()

# we map the shared memory object to a python buffer
#mm = mmap.mmap( 1024, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE) 

# We read data written by C
#print(mm.readline().decode())

#mmap.mmap(-1, 1024, access=mmap.ACCESS_COPY) #tagname="myregion")

# we can read wht the C program has written and print it out
input1 = content #mm.readline().decode();
#
print("the message sent from planet C was the following: ", input1)
'''
#---------------------------------------------------------------------
#input1 = message

#---------------------------------------------------------------------
# we open the file that serves to transfer inputs from C to python

with open("/home/summer/temp_skyfall.txt", "r") as fd:
	# we read the entire content of the file
	content = fd.readline()

	#print(f"\n before decoding, the type of input1 {content} is {type(content).__name__} \n")
	# we decode the content of the file
	input1_LThash = content #.decode()

	#print(f"\n After decoding, the type of input1 {input1_LThash} is {type(input1_LThash).__name__} \n")
	

	# we print the content of the file
	#print("\n the content of input1 is ", input1_LThash)



# the determinant of the lattice matrix
	
def main(n, d, input2):
	# All data inputs have to be sets
	
	#--------------------------------------------------------------------------------------------	
	# Because C does not support Sets natively, we consider inputs of the functions to be strings
	# then we add each input to a set before processing such input further
	set_input2 = {input2}

	
	# we define a lthash3 object to compute digest
	lthash3 = LtHash(n,d)

	
	# we need to set the digest of lthash3 to be input1
	# we use ast to recover the list (hash digest is a list)
	input1_list = ast.literal_eval(input1_LThash)

	#-----------------------------------------------------------------------------------
	#print(f"\n the recovered list from input1 is {input1_list} \n")

	#print(f"the type of recovered input1_list is {type(input1_list).__name__}")


	#---------------------------------------------------------------------------------
	# we define a novel lthash object to add our string digest
	#lthash3.digest = input1_list
	lthash_input1 = LtHash(n,d)
	lthash_input1.digest = input1_list
	#print("lthash_input1 digest output value is ", lthash_input1.digest)


	# We first add the the value of lthash_input1
	lthash3.add(lthash_input1)
	#print("lthash3_digest current output value is ", lthash3.digest)

	
	# All our inputs are turned to sets right away before computing the LThash
	# lthash3.add_data(set_input2) #view the code of add_data in lthash.py
	#lthash3.add_data(set_input2)

	# We compute LThash(input2) to realize H2(input1) + H2(input2)
	lthash_input2 = LtHash(n,d)
	lthash_input2.eval(set_input2)
	
	#
	lthash3.add(lthash_input2)


	#print("lthash3_digest output value is ", lthash3.digest)


	#lthash3.add_data(input2) #view the code of add_data in lthash.py	

	#-------------------------------------------------------------------
	# We Work the output
	#-------------------------------------------------------------------
	
	output = lthash3.digest
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
main(n, d, input2)
