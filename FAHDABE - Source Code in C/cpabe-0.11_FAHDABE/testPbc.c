#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <pbc.h>


#define TYPE_A_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"


int main()
{
	//we would like to check how to initialize a pairing => Initialize the two groups generator and the order of the different groups

pairing_t p; //this variable will help us to initialize our pairings and groups and elements

char* pairing_description=0;
//
pairing_description = strdup(TYPE_A_PARAMS);
//
pairing_init_set_buf(p, pairing_description, strlen(pairing_description));

//now we initialise an element for each group G1 and G2
element_t g, h;

element_init_G1(g, p); //belongs to G1
element_init_G2(h, p); //belongs to G2

element_random(g);//g random element of G1
element_random(h);//h random element of G2

element_printf("value of g--->%d\n",g);
element_printf("value of h--->%d\n",h);

printf("We print the variables \n g---> %\n \n h---> %f\n",g,h);


}
