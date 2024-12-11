from charm.toolbox.pairinggroup import ZR, GT
from charm.toolbox.pairinggroup import PairingGroup

from FAHDABE import FAHDABE24MAABE_CP


def main():
    groupObj = PairingGroup('SS512')

    fahdabe_obj = FAHDABE24MAABE_CP(groupObj)

    (pk, mk) = fahdabe_obj.setup()

    epsilon_value = 'epsilon'
    hidden_epsilon = fahdabe_obj.keygen0(epsilon_value)

    # set of attributes
    attrs = ['ONE', 'TWO', 'FOUR']

    # access_policy = '((four and three) and (three and one))'
    one_hidden = fahdabe_obj.hide_string_with_epsilon(string_to_hide='ONE', epsilon=epsilon_value)
    two_hidden = fahdabe_obj.hide_string_with_epsilon(string_to_hide='TWO', epsilon=epsilon_value)
    three_hidden = fahdabe_obj.hide_string_with_epsilon(string_to_hide='THREE', epsilon=epsilon_value)
    four_hidden = fahdabe_obj.hide_string_with_epsilon(string_to_hide='FOUR', epsilon=epsilon_value)

    # access_policy = f"(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden}))"
    # [500, 578, 455, 466, 829, 359, 432, 27]
    # [174, 400, 417, 889, 75, 661, 816, 772]
    # [645, 638, 945, 157, 772, 660, 789, 238]

    # case-sensitive since we do the hashing
    access_policy = f'(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden}))'

    if debug:
        print("Unhidden Attributes =>", attrs, "\n")
        print("Policy =>", access_policy, "\n")

    user_gid = 'gid'
    attd = 'dummy'

    do_key = fahdabe_obj.keygen1(pk, mk, user_gid, epsilon_value, attd)
    #
    # S_hidden = fahdabe_obj.hide(do_key, attrs)
    #
    hash_user_gid = fahdabe_obj.group.hash(str(user_gid), type=ZR)
    #
    # WE consider three AAs
    # set of attributes
    attrs_1 = ['ONE']
    S_hidden_1 = fahdabe_obj.hide(do_key, attrs_1)
    aa_key_1 = fahdabe_obj.keygen2(pk, S_hidden_1, hash_user_gid)

    # set of attributes
    attrs_2 = ['TWO']
    S_hidden_2 = fahdabe_obj.hide(do_key, attrs_2)
    aa_key_2 = fahdabe_obj.keygen2(pk, S_hidden_2, hash_user_gid)

    # set of attributes
    attrs_3 = ['FOUR']
    S_hidden_3 = fahdabe_obj.hide(do_key, attrs_3)
    aa_key_3 = fahdabe_obj.keygen2(pk, S_hidden_3, hash_user_gid)
    #
    input_aa_key = list()
    input_aa_key.append(aa_key_1)
    input_aa_key.append(aa_key_2)
    input_aa_key.append(aa_key_3)
    # input_aa_key[0]= aa_key_1
    # input_aa_key[1] = aa_key_2
    # input_aa_key[2] = aa_key_3

    if debug:
        print(f"Hidden Attributes => \n {S_hidden_1} \n {S_hidden_2} \n {S_hidden_3} \n")

    rrd_key = fahdabe_obj.keygen3(input_aa_key)
    #
    sk_du, hk_du = fahdabe_obj.keygen4(do_key, rrd_key)
    #
    rand_msg = fahdabe_obj.group.random(GT)
    #
    ct_do = fahdabe_obj.encrypt1(pk, rand_msg, access_policy, epsilon_value, attd)
    #
    ct_rrd = fahdabe_obj.encrypt2(pk, ct_do)
    #
    TC, helper_decryption_term, ct_do_pr = fahdabe_obj.transform(ct_rrd, hk_du)

    rec_msg = fahdabe_obj.udecrypt(TC, helper_decryption_term, ct_do_pr, sk_du)

    # if debug: print("\n\nCiphertext...\n")
    # groupObj.debug(ct)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"

    if debug is True:
        print(f" Original msg: {rand_msg} \n")
        print(f" msg recovered: {rec_msg} \n")
    print("Successful Decryption!!!")


if __name__ == "__main__":
    debug = True
    main()