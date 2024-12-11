'''
| --- ADAPTED VERSION ---
| Authors:      Arthur Sandor Voundi Koe
| Date:         12/2024
|
| FROM
|
| https://github.com/DoreenRiepel/FABEO  
| Authors:      Doreen Riepel
| Date:         06/2023
|
'''

import random

from charm.toolbox.pairinggroup import PairingGroup, GT

import time

import sys

import pandas as pd

from FABEO.abenc_maabe_rw15 import MaabeRW15, merge_dicts
from FABEO.abenc_maabe_yj14 import MAABE
from FABEO.msp import MSP

from FABEO.fabeo22cp import FABEO22CPABE
from BSWCPABE import CPABE_BSW07
from FAHDABE import FAHDABE24MAABE_CP
from EASYABE import easyabe23cp

# global variable to hide access policy or not (managed in code)
hide_policy = False

# global variable for the epsilon string to hide attributes

epsilon = 'epsilon'

# global variable to output data as CSV
output_data = {
    'Scheme': list(),
    '#attributes': list(),
    'Setup (ms)': list(),
    'Keygen (ms)': list(),
    'Encrypt (ms)': list(),
    'Decrypt (ms)': list(),
    'Ciphertext size (bytes)': list()
}

# global variable to measure the time/size of encryption and decryption for intermediate ciphertexts in FAHDABE
fahdabe_cph_data = {
    'Scheme': list(),
    '#attributes': list(),
    'Keygen1 (ms)': list(),
    'Keygen2 (ms)': list(),
    'Keygen3 (ms)': list(),
    'Keygen4 (ms)': list(),
    'Encrypt1 (ms)': list(),
    'Encrypt2 (ms)': list(),
    'Transform (ms)': list(),
    'Decrypt (ms)': list(),
    'Ciphertext_DO size (bytes)': list(),
    'Ciphertext_RRD size (bytes)': list()
}


def measure_average_times(abe, attr_list, policy_str, k1, k2, k3, msg, N=5, epsilon_value='epsilon', user_gid='gid',
                          attd='dummy'):
    sum_setup = 0
    sum_enc = 0
    sum_keygen = 0
    sum_dec = 0

    # for FAHDABE
    sum_keygen_1 = 0
    sum_keygen_2 = 0
    sum_keygen_3 = 0
    sum_keygen_4 = 0
    sum_transform = 0
    sum_decrypt = 0
    sum_enc_1 = 0
    sum_enc_2 = 0
    size_do_cph = 0
    size_rrd_cph = 0

    # for Rouselakis and Waters (and schemes with Authority Setup)
    sum_auth_setup = 0
    size_cph_rw = 0

    # for Kan Yang and Xiaohua Jia
    sum_reg_user = 0
    size_cph_kyxj = 0

    # for FABEO
    size_cph_fabeo = 0

    # for EASYABE
    size_cph_easyabe = 0

    # for BSW CPABE
    size_cph_bsw = 0

    for i in range(N):

        # for FAHDABE
        if abe.name == "FAHDABE MA-CP-ABE":

            # setup time
            start_setup = time.time()
            (pk, msk) = abe.setup()
            end_setup = time.time()
            time_setup = end_setup - start_setup
            sum_setup += time_setup

            # DO keygen1 time
            start_keygen_1 = time.time()
            do_key = abe.keygen1(pk, msk, user_gid, epsilon_value, attd)
            end_keygen_1 = time.time()
            time_keygen = end_keygen_1 - start_keygen_1
            sum_keygen += time_keygen
            sum_keygen_1 += time_keygen

            # AA keygen2 time
            start_keygen_2 = time.time()
            # splitting the list of attributes into three sublists
            list_length = int(len(attr_list) / 3)
            attr_list_1 = attr_list[0:list_length]
            attr_list_2 = attr_list[list_length:(2 * list_length)]
            attr_list_3 = attr_list[(2 * list_length):len(attr_list)]

            attr_list_1_hidden = abe.hide(do_key, attr_list_1)
            attr_list_2_hidden = abe.hide(do_key, attr_list_2)
            attr_list_3_hidden = abe.hide(do_key, attr_list_3)

            aa_key_1 = abe.keygen2(pk, attr_list_1_hidden, user_gid)
            aa_key_2 = abe.keygen2(pk, attr_list_2_hidden, user_gid)
            aa_key_3 = abe.keygen2(pk, attr_list_3_hidden, user_gid)

            end_keygen_2 = time.time()
            time_keygen = end_keygen_2 - start_keygen_2
            sum_keygen += time_keygen
            sum_keygen_2 += time_keygen

            # RRD keygen3 time
            start_keygen_3 = time.time()
            rrd_key = abe.keygen3((aa_key_1, aa_key_2, aa_key_3))
            # print(f"attributes: {rrd_key['S_hidden']} \n")
            end_keygen_3 = time.time()
            time_keygen = end_keygen_3 - start_keygen_3
            sum_keygen += time_keygen
            sum_keygen_3 += time_keygen

            # DU keygen4 time
            start_keygen_4 = time.time()
            sk_du, hk_du = abe.keygen4(do_key, rrd_key)
            end_keygen_4 = time.time()
            time_keygen = end_keygen_4 - start_keygen_4
            sum_keygen += time_keygen
            sum_keygen_4 += time_keygen

            # DO encryption time
            start_enc_1 = time.time()

            # hide the attributes in the policy

            ctxt_1 = abe.encrypt1(pk, msg, policy_str, epsilon_value, attd)
            end_enc_1 = time.time()
            time_enc = end_enc_1 - start_enc_1
            sum_enc += time_enc
            sum_enc_1 += time_enc

            # size of FAHDABE ciphertext
            size_do_cph += len(abe.group.serialize(ctxt_1['cs'], compression=False)) + len(
                abe.group.serialize(ctxt_1['c'], compression=False)) \
                           + len(abe.group.serialize(ctxt_1['c_attd'], compression=False)) + len(
                abe.group.serialize(ctxt_1['cp_attd'], compression=False)) + \
                           len(abe.group.serialize(ctxt_1['witness'], compression=False)) + len(
                str.encode(ctxt_1['policy'], encoding='utf-8'))

            # Cloud Encryption time
            start_enc_2 = time.time()
            ctxt_2 = abe.encrypt2(pk, ct_do=ctxt_1)
            end_enc_2 = time.time()
            time_enc = end_enc_2 - start_enc_2
            sum_enc += time_enc
            sum_enc_2 += time_enc

            size_rrd_cph += len(abe.group.serialize(ctxt_2['c_rrd'], compression=False)) + len(
                abe.group.serialize(ctxt_2['cs_rrd'], compression=False)) + len(
                abe.group.serialize(ctxt_2['cs_do'], compression=False)) + len(
                abe.group.serialize(ctxt_2['c_do'], compression=False)) \
                            + len(abe.group.serialize(ctxt_2['c_attd'], compression=False)) + len(
                abe.group.serialize(ctxt_2['cp_attd'], compression=False)) + \
                            len(abe.group.serialize(ctxt_2['witness'], compression=False)) + len(
                str.encode(ctxt_2['policy'], encoding='utf-8'))
            for value in ctxt_2['C_y'].values():
                size_rrd_cph += len(abe.group.serialize(value, compression=False))

            for value in ctxt_2['C_y_pr'].values():
                size_rrd_cph += len(abe.group.serialize(value, compression=False))

            # Cloud Decryption time
            start_dec_1 = time.time()
            TC, helper_term, ct_do_pr = abe.transform(ctxt_2, hk_du)
            end_dec_1 = time.time()
            time_dec = end_dec_1 - start_dec_1
            sum_dec += time_dec
            sum_transform += time_dec

            # DU Decryption time
            start_dec_2 = time.time()
            rec_msg = abe.udecrypt(TC, helper_term, ct_do_pr, sk_du)
            end_dec_2 = time.time()
            time_dec = end_dec_2 - start_dec_2
            sum_dec += time_dec
            sum_decrypt += time_dec

            # sanity check
            if rec_msg is False:
                print(f"Decryption in FAHDABE failed with {rec_msg}.")
                # exit(-1)

        elif abe.name == "ROUSELAKIS-WATERS":
            # setup time
            start_setup = time.time()
            pk = abe.setup()
            end_setup = time.time()
            time_setup = end_setup - start_setup
            sum_setup += time_setup

            # Authority Setup
            start_setup_1 = time.time()
            (public_key1, secret_key1) = abe.authsetup(pk, 'AA1')
            (public_key2, secret_key2) = abe.authsetup(pk, 'AA2')
            (public_key3, secret_key3) = abe.authsetup(pk, 'AA3')
            public_keys = {'AA1': public_key1, 'AA2': public_key2, 'AA3': public_key3}
            end_setup_1 = time.time()
            time_setup = end_setup_1 - start_setup_1
            sum_setup += time_setup
            sum_auth_setup += time_setup

            # Keygen
            start_keygen = time.time()
            list_length = int(len(attr_list) / 3)
            attr_list_1 = []  # attr_list[0:list_length]
            attr_list_2 = []  # attr_list[list_length:(2 * list_length)]
            attr_list_3 = []  # attr_list[(2 * list_length):len(attr_list)]

            for index in range(len(attr_list)):
                if '@AA1' in attr_list[index]:
                    attr_list_1.append(attr_list[index])

                if '@AA2' in attr_list[index]:
                    attr_list_2.append(attr_list[index])

                if '@AA3' in attr_list[index]:
                    attr_list_3.append(attr_list[index])

            # # Assign attributes to specific AA
            # for i in range(len(attr_list_1)):
            #     attr_list_1[i] = attr_list_1[i] + '@AA1'
            #
            # for i in range(len(attr_list_2)):
            #     attr_list_2[i] = attr_list_2[i] + '@AA2'
            #
            # for i in range(len(attr_list_3)):
            #     attr_list_3[i] = attr_list_3[i] + '@AA3'
            #
            # print(attr_list_1)
            # print(attr_list_2)
            # print(attr_list_3)
            user_keys1 = abe.multiple_attributes_keygen(pk, secret_key1, user_gid, attr_list_1)
            user_keys2 = abe.multiple_attributes_keygen(pk, secret_key2, user_gid, attr_list_2)
            user_keys3 = abe.multiple_attributes_keygen(pk, secret_key3, user_gid, attr_list_3)
            user_keys = {'GID': user_gid, 'keys': merge_dicts(user_keys1, user_keys2, user_keys3)}
            end_keygen = time.time()
            time_keygen = end_keygen - start_keygen
            sum_keygen += time_keygen

            # Encrypt
            start_enc = time.time()
            ctxt = abe.encrypt(pk, public_keys, msg, policy_str)
            end_enc = time.time()
            time_enc = end_enc - start_enc
            sum_enc += time_enc

            size_cph_rw += len(abe.group.serialize(ctxt['C0'], compression=False)) + len(
                str.encode(ctxt['policy'], encoding='utf-8'))

            for value in ctxt['C1'].values():
                size_cph_rw += len(abe.group.serialize(value, compression=False))

            for value in ctxt['C2'].values():
                size_cph_rw += len(abe.group.serialize(value, compression=False))

            for value in ctxt['C3'].values():
                size_cph_rw += len(abe.group.serialize(value, compression=False))

            for value in ctxt['C4'].values():
                size_cph_rw += len(abe.group.serialize(value, compression=False))

            # Decrypt
            start_dec = time.time()
            rec_msg = abe.decrypt(pk, user_keys, ctxt)
            end_dec = time.time()
            time_dec = end_dec - start_dec
            sum_dec += time_dec

            if rec_msg != msg:
                print("Decryption in Rouselakis-Waters failed.")

        elif abe.name == "KANYANG-XIAOHUAJIA":
            # setup time
            start_setup = time.time()
            GPP, GMK = abe.setup()
            end_setup = time.time()
            time_setup = end_setup - start_setup
            sum_setup += time_setup
            # ----------------------------------------------------------
            # Register a single user (we only generate a single user secret key)
            start_setup_1 = time.time()
            users = {}  # public user data
            AADict = {}  # dictionary of authorities
            #
            user_1 = {
                'id': 'user_1', 'authoritySecretKeys_AA1': {}, 'authoritySecretKeys_AA2': {},
                'authoritySecretKeys_AA3': {}, 'keys': None
            }
            #
            user_1['keys'], users[user_1['id']] = abe.registerUser(GPP)
            #
            end_setup_1 = time.time()
            time_setup = end_setup_1 - start_setup_1
            sum_setup += time_setup
            sum_reg_user += time_setup
            # ------------------------------------------------------------
            # register three AA (Attribute Authorities)
            start_setup_1 = time.time()
            #
            # splitting the list of attributes into three sublists
            list_length = int(len(attr_list) / 3)
            attr_list_1 = attr_list[0:list_length]
            attr_list_2 = attr_list[list_length:(2 * list_length)]
            attr_list_3 = attr_list[(2 * list_length):len(attr_list)]
            #
            #
            AA1 = "AA_1"
            abe.setupAuthority(GPP, AA1, attr_list_1, AADict)
            #
            AA2 = "AA_2"
            abe.setupAuthority(GPP, AA2, attr_list_2, AADict)
            #
            AA3 = "AA_3"
            abe.setupAuthority(GPP, AA3, attr_list_3, AADict)
            #
            end_setup_1 = time.time()
            time_setup = end_setup_1 - start_setup_1
            sum_setup += time_setup
            sum_auth_setup += time_setup

            # Keygen
            start_keygen = time.time()
            # AA1
            for attr in range(len(attr_list_1)):
                abe.keygen(GPP, AADict[AA1], attr_list_1[attr], users[user_1['id']], user_1['authoritySecretKeys_AA1'])

            # AA2
            for attr in range(len(attr_list_2)):
                abe.keygen(GPP, AADict[AA2], attr_list_2[attr], users[user_1['id']], user_1['authoritySecretKeys_AA2'])

            # AA3
            for attr in range(len(attr_list_3)):
                abe.keygen(GPP, AADict[AA3], attr_list_3[attr], users[user_1['id']], user_1['authoritySecretKeys_AA3'])

            end_keygen = time.time()
            time_keygen = end_keygen - start_keygen
            sum_keygen += time_keygen

            # encrypt
            start_enc = time.time()

            # for simplicity, we reconstruct sub-policies using attributes
            policy_str_1 = '(' + attr_list_1[0]
            policy_str_2 = '(' + attr_list_2[0]
            policy_str_3 = '(' + attr_list_3[0]
            for att in attr_list_1[1:]:
                policy_str_1 += ' and ' + att  # {i}'
            policy_str_1 += ')'

            for att in attr_list_2[1:]:
                policy_str_2 += ' and ' + att  # {i}'
            policy_str_2 += ')'

            for att in attr_list_3[1:]:
                policy_str_3 += ' and ' + att  # {i}'
            policy_str_3 += ')'

            # For simplicity, we assume AAi manages attributes in the access policy over the content key ki and

            # ctxt_1 = abe.encrypt(GPP, policy_str_1, k1, AADict[AA1])
            ctxt_1 = abe.encrypt(GPP, policy_str_1, k1, AADict[AA1])
            ctxt_2 = abe.encrypt(GPP, policy_str_2, k2, AADict[AA2])
            ctxt_3 = abe.encrypt(GPP, policy_str_3, k3, AADict[AA3])

            end_enc = time.time()
            time_enc = end_enc - start_enc
            sum_enc += time_enc
            #
            # encryption ciphertext size
            avg_C1 = (len(abe.group.serialize(ctxt_1['C1'], compression=False)) +
                      len(abe.group.serialize(ctxt_2['C1'], compression=False)) +
                      len(abe.group.serialize(ctxt_3['C1'], compression=False))) / 3
            #
            avg_C2 = (len(abe.group.serialize(ctxt_1['C2'], compression=False)) + len(
                abe.group.serialize(ctxt_2['C2'], compression=False)) + len(
                abe.group.serialize(ctxt_3['C2'], compression=False))) / 3
            #
            avg_C3 = (len(abe.group.serialize(ctxt_1['C3'], compression=False)) + len(
                abe.group.serialize(ctxt_2['C3'], compression=False)) + len(
                abe.group.serialize(ctxt_3['C3'], compression=False))) / 3

            avg_policy = (len(str.encode(ctxt_1['policy'], encoding='utf-8'))
                          + len(str.encode(ctxt_2['policy'], encoding='utf-8'))
                          + len(str.encode(ctxt_3['policy'], encoding='utf-8'))) / 3

            size_cph_kyxj += avg_C1 + avg_C2 + avg_C3 + avg_policy
            # -----------------------------------------------------------------------------
            size_cph_kyxj_C_1 = 0
            size_cph_kyxj_C_2 = 0
            size_cph_kyxj_C_3 = 0
            #
            for value in ctxt_1['C'].values():
                size_cph_kyxj_C_1 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_2['C'].values():
                size_cph_kyxj_C_2 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_3['C'].values():
                size_cph_kyxj_C_3 += len(abe.group.serialize(value, compression=False))
            #
            size_cph_kyxj += (size_cph_kyxj_C_1 + size_cph_kyxj_C_2 + size_cph_kyxj_C_3) / 3
            # --------------------------------------------------------------------------------
            size_cph_kyxj_CS_1 = 0
            size_cph_kyxj_CS_2 = 0
            size_cph_kyxj_CS_3 = 0
            #
            for value in ctxt_1['CS'].values():
                size_cph_kyxj_CS_1 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_2['CS'].values():
                size_cph_kyxj_CS_2 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_3['CS'].values():
                size_cph_kyxj_CS_3 += len(abe.group.serialize(value, compression=False))
            #
            size_cph_kyxj += (size_cph_kyxj_CS_1 + size_cph_kyxj_CS_2 + size_cph_kyxj_CS_3) / 3
            # -------------------------------------------------------------------------------
            size_cph_kyxj_D_1 = 0
            size_cph_kyxj_D_2 = 0
            size_cph_kyxj_D_3 = 0
            #
            for value in ctxt_1['D'].values():
                size_cph_kyxj_D_1 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_2['D'].values():
                size_cph_kyxj_D_2 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_3['C'].values():
                size_cph_kyxj_D_3 += len(abe.group.serialize(value, compression=False))
            #
            size_cph_kyxj += (size_cph_kyxj_D_1 + size_cph_kyxj_D_2 + size_cph_kyxj_D_3) / 3
            # -------------------------------------------------------------------------------
            size_cph_kyxj_DS_1 = 0
            size_cph_kyxj_DS_2 = 0
            size_cph_kyxj_DS_3 = 0
            #
            for value in ctxt_1['DS'].values():
                size_cph_kyxj_DS_1 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_2['DS'].values():
                size_cph_kyxj_DS_2 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_3['DS'].values():
                size_cph_kyxj_DS_3 += len(abe.group.serialize(value, compression=False))
            #
            size_cph_kyxj += (size_cph_kyxj_DS_1 + size_cph_kyxj_DS_2 + size_cph_kyxj_DS_3) / 3

            # Decrypt
            start_dec = time.time()
            rec_msg_1 = abe.decrypt(GPP, ctxt_1, user_1, 'authoritySecretKeys_AA1')
            rec_msg_2 = abe.decrypt(GPP, ctxt_2, user_1, 'authoritySecretKeys_AA2')
            rec_msg_3 = abe.decrypt(GPP, ctxt_3, user_1, 'authoritySecretKeys_AA3')
            end_dec = time.time()
            time_dec = end_dec - start_dec
            sum_dec += time_dec

            assert rec_msg_1 == k1, 'FAILED DECRYPTION!'
            assert rec_msg_2 == k2, 'FAILED DECRYPTION!'
            assert rec_msg_3 == k3, 'FAILED DECRYPTION!'

        elif abe.name == "EASYABE":
            # Setup time
            start_setup = time.time()
            (pk, msk) = abe.setup()
            end_setup = time.time()
            time_setup = end_setup - start_setup
            sum_setup += time_setup

            # encryption time
            start_enc = time.time()
            A = abe.get_A(policy_str)
            ctxt = abe.encrypt(pk, A, msg.__str__())
            end_enc = time.time()
            time_enc = end_enc - start_enc
            sum_enc += time_enc

            size_cph_easyabe += (len(abe.group.serialize(ctxt['c1'], compression=False)) +
                                 len(abe.group.serialize(ctxt['g2_s'], compression=False)))

            for value in ctxt['c2c3'].values():
                size_cph_easyabe += len(str.encode(value, encoding='utf-8'))

            for value in ctxt['hws'].values():
                size_cph_easyabe += len(abe.group.serialize(value, compression=False))

            # keygen time
            start_keygen = time.time()
            w = abe.get_attr_string(attr_list)
            key = abe.keygen(pk, msk, w)
            end_keygen = time.time()
            time_keygen = end_keygen - start_keygen
            sum_keygen += time_keygen

            # decryption time
            start_dec = time.time()
            rec_msg = abe.decrypt(ctxt, key)
            end_dec = time.time()
            time_dec = end_dec - start_dec
            sum_dec += time_dec

            # sanity check
            assert rec_msg != False, 'Decryption in EASYABE failed !'

        else:
            # setup time
            start_setup = time.time()
            (pk, msk) = abe.setup()
            end_setup = time.time()
            time_setup = end_setup - start_setup
            sum_setup += time_setup

            # encryption time
            start_enc = time.time()
            ctxt = abe.encrypt(pk, msg, policy_str)
            # print(f'normal cpabe access policy in measurements.py: {policy_str}\n')
            # print(f'normal cpabe original msg in measurements.py: {msg}\n')
            end_enc = time.time()
            time_enc = end_enc - start_enc
            sum_enc += time_enc

            if abe.name == "BSW07 CP-ABE":
                size_cph_bsw += len(abe.group.serialize(ctxt['C_tilde'], compression=False)) + len(
                    abe.group.serialize(ctxt['C'], compression=False)) + len(
                    str.encode(ctxt['policy'], encoding='utf-8'))
                for value in ctxt['Cy'].values():
                    size_cph_bsw += len(abe.group.serialize(value, compression=False))
                for value in ctxt['Cyp'].values():
                    size_cph_bsw += len(abe.group.serialize(value, compression=False))
                for value in ctxt['attributes']:
                    size_cph_bsw += len(str.encode(value, encoding='utf-8'))

            if abe.name == "FABEO CP-ABE":
                size_cph_fabeo += len(abe.group.serialize(ctxt['g2_s1'], compression=False)) + len(
                    abe.group.serialize(ctxt['g2_sprime'], compression=False)) + sys.getsizeof(
                    ctxt['policy'])
                for value in ctxt['ct'].values():
                    size_cph_fabeo += len(abe.group.serialize(value, compression=False))

            # keygen time
            start_keygen = time.time()
            key = abe.keygen(pk, msk, attr_list)
            # print(f'normal cpabe attribute list in measurements.py: {attr_list}\n')
            end_keygen = time.time()
            time_keygen = end_keygen - start_keygen
            sum_keygen += time_keygen

            # decryption time
            start_dec = time.time()
            rec_msg = abe.decrypt(pk, ctxt, key)
            # print(f'normal recovered msg in measurements.py: {msg}\n')
            end_dec = time.time()
            time_dec = end_dec - start_dec
            sum_dec += time_dec

            # sanity check
            if rec_msg is False:
                print("Decryption in CPABE failed.")

    # compute average time
    time_setup = sum_setup / N
    time_enc = sum_enc / N
    time_keygen = sum_keygen / N
    time_dec = sum_dec / N

    time_keygen_1 = sum_keygen_1 / N
    time_keygen_2 = sum_keygen_2 / N
    time_keygen_3 = sum_keygen_3 / N
    time_keygen_4 = sum_keygen_4 / N
    time_enc_1 = sum_enc_1 / N
    time_enc_2 = sum_enc_2 / N
    time_dec_1 = sum_transform / N
    time_dec_2 = sum_decrypt / N

    time_auth_setup = sum_auth_setup / N
    time_reg_user = sum_reg_user / N

    avg_size_cph_do = size_do_cph / N
    avg_size_cph_rrd = size_rrd_cph / N

    avg_size_cph_rw = size_cph_rw / N
    avg_size_cph_kyxj = size_cph_kyxj / N
    avg_size_cph_bsw = size_cph_bsw / N
    avg_size_cph_fabeo = size_cph_fabeo / N
    avg_size_cph_easyabe = size_cph_easyabe / N

    return [time_setup, time_keygen, time_enc, time_dec, time_keygen_1, time_keygen_2,
            time_keygen_3, time_keygen_4, time_enc_1, time_enc_2, time_dec_1, time_dec_2, time_auth_setup,
            time_reg_user, avg_size_cph_do, avg_size_cph_rrd, avg_size_cph_rw, avg_size_cph_kyxj,
            avg_size_cph_bsw, avg_size_cph_fabeo, avg_size_cph_easyabe]


def print_running_time(scheme_name, times, attr_number):
    print('{:<26}'.format(scheme_name) + str(attr_number).format(' ') + '         ' + format(times[0] * 1000,
                                                                                             '7.2f') + '    ' + format(
        times[1] * 1000,
        '7.2f') + '  ' + format(
        times[2] * 1000, '7.2f') + '  ' + format(times[3] * 1000, '7.2f'))


def run_all(pairing_group, policy_size, policy_str, attr_list, hidden_policy, rw_policy_string, rw_attr_list, k1, k2,
            k3, msg):
    algos = ['#attributes', 'Setup (ms)', 'KeyGen (ms)', 'Enc (ms)', 'Dec (ms)']

    n1, n2, m, i = get_par(pairing_group, policy_str, attr_list)

    print('Running times (msp) curve SS512: n1={}  n2={}  m={}  I={}'.format(n1, n2, m, i))
    algo_string = 'CP-ABE {:<13}'.format('') + '  ' + algos[0] + '     ' + algos[1] + '    ' + algos[2] + '     ' + \
                  algos[3] + '      ' + \
                  algos[4]
    print('-' * 80)
    print(algo_string)
    print('-' * 80)
    #
    bsw07_cp = CPABE_BSW07(pairing_group)
    bsw07_cp_times = measure_average_times(bsw07_cp, attr_list, policy_str, k1, k2, k3, msg)
    print_running_time(bsw07_cp.name, bsw07_cp_times, len(attr_list))
    print('{:<26}'.format('   | cph_size (bytes)') + str(len(attr_list)).format(' ') + '{:<9}'.format(
        '') + '      -    ' +
          '      -' + format(' ') + '  ' + format(bsw07_cp_times[18], '5.1f') + format(' '))
    output_data['Scheme'].append(bsw07_cp.name)
    output_data['#attributes'].append(len(attr_list))
    output_data['Setup (ms)'].append(bsw07_cp_times[0])
    output_data['Keygen (ms)'].append(bsw07_cp_times[1])
    output_data['Encrypt (ms)'].append(bsw07_cp_times[2])
    output_data['Decrypt (ms)'].append(bsw07_cp_times[3])
    output_data['Ciphertext size (bytes)'].append(bsw07_cp_times[18])
    #
    fahdabe24_cp = FAHDABE24MAABE_CP(pairing_group)
    fahdabe24_cp_times = measure_average_times(fahdabe24_cp, attr_list, hidden_policy, k1, k2, k3, msg)
    print_running_time(fahdabe24_cp.name, fahdabe24_cp_times, len(attr_list))
    print('{:<26}'.format('   | keygen 1') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -    ' +
          format(fahdabe24_cp_times[4] * 1000, '7.2f') + '        -  ' + format(' ') + '  ' + format(
        '  ') + ' - ' + format(
        ' '))
    print('{:<26}'.format('   | keygen 2') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -    ' +
          format(fahdabe24_cp_times[5] * 1000, '7.2f') + '        -  ' + format('  ') + '  ' + format(
        ' ') + ' -  ' + format(
        ' '))
    print('{:<26}'.format('   | keygen 3') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -    ' +
          format(fahdabe24_cp_times[6] * 1000, '7.2f') + '        -  ' + format('  ') + '  ' + format(
        ' ') + ' -  ' + format(
        ' '))
    print('{:<26}'.format('   | keygen 4') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -    ' +
          format(fahdabe24_cp_times[7] * 1000, '7.2f') + '        -  ' + format('  ') + '  ' + format(
        ' ') + ' -  ' + format(
        ' '))
    print('{:<26}'.format('   | encrypt 1') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + ' ' + '{:<6}'.format('') + '  -  ' +
          format(fahdabe24_cp_times[8] * 1000, '7.2f') + '        - ' + format(' '))
    print('{:<26}'.format('   | encrypt 2') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + ' ' + '{:<6}'.format('') + '  -  ' +
          format(fahdabe24_cp_times[9] * 1000, '7.2f') + '        - ' + format(' '))

    print('{:<26}'.format('   | transform') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + ' -  ' + '      -  ' +
          format(fahdabe24_cp_times[10] * 1000, '7.2f'))

    print('{:<26}'.format('   | udecrypt') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + ' -  ' + '      -  ' +
          format(fahdabe24_cp_times[11] * 1000, '7.2f'))

    print('{:<26}'.format('   | cph_do_size (bytes)') + str(len(attr_list)).format(' ') + '{:<9}'.format(
        '') + '      -    ' +
          '      -' + format(' ') + '  ' + format(fahdabe24_cp_times[14], '5.1f') + format(' '))

    print('{:<26}'.format('   | cph_rrd_size (bytes)') + str(len(attr_list)).format(' ') + '{:<9}'.format(
        '') + '      -    ' +
          '      -' + format(' ') + '  ' + format(fahdabe24_cp_times[15], '5.1f') + format(''))
    #
    output_data['Scheme'].append(fahdabe24_cp.name)
    output_data['#attributes'].append(len(attr_list))
    output_data['Setup (ms)'].append(fahdabe24_cp_times[0])
    output_data['Keygen (ms)'].append(fahdabe24_cp_times[1])
    output_data['Encrypt (ms)'].append(fahdabe24_cp_times[2])
    output_data['Decrypt (ms)'].append(fahdabe24_cp_times[3])
    output_data['Ciphertext size (bytes)'].append(fahdabe24_cp_times[15])
    #
    fahdabe_cph_data['Scheme'].append(fahdabe24_cp.name)
    fahdabe_cph_data['#attributes'].append(len(attr_list))
    fahdabe_cph_data['Keygen1 (ms)'].append(fahdabe24_cp_times[4])
    fahdabe_cph_data['Keygen2 (ms)'].append(fahdabe24_cp_times[5])
    fahdabe_cph_data['Keygen3 (ms)'].append(fahdabe24_cp_times[6])
    fahdabe_cph_data['Keygen4 (ms)'].append(fahdabe24_cp_times[7])
    fahdabe_cph_data['Encrypt1 (ms)'].append(fahdabe24_cp_times[8])
    fahdabe_cph_data['Encrypt2 (ms)'].append(fahdabe24_cp_times[9])
    fahdabe_cph_data['Transform (ms)'].append(fahdabe24_cp_times[10])
    fahdabe_cph_data['Decrypt (ms)'].append(fahdabe24_cp_times[11])
    fahdabe_cph_data['Ciphertext_DO size (bytes)'].append(fahdabe24_cp_times[14])
    fahdabe_cph_data['Ciphertext_RRD size (bytes)'].append(fahdabe24_cp_times[15])
    #
    maabe_rw15_cp = MaabeRW15(pairing_group)
    maabe_rw15_cp_times = measure_average_times(maabe_rw15_cp, rw_attr_list, rw_policy_string, k1, k2, k3, msg)
    print_running_time(maabe_rw15_cp.name, maabe_rw15_cp_times, len(rw_attr_list))
    print('{:<26}'.format('   | authority setup') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(maabe_rw15_cp_times[12] * 1000, '7.2f') + '          -' + '        -  ' + format(' ') + '  ' + format(
        '  ') + ' - ' + format(
        ' '))
    print('{:<26}'.format('   | cph_size (bytes)') + str(len(attr_list)).format(' ') + '{:<7}'.format(
        '') + '        -    ' +
          '      -' + format(' ') + '  ' + format(maabe_rw15_cp_times[16], '5.1f') + format(''))
    #
    output_data['Scheme'].append(maabe_rw15_cp.name)
    output_data['#attributes'].append(len(attr_list))
    output_data['Setup (ms)'].append(maabe_rw15_cp_times[0])
    output_data['Keygen (ms)'].append(maabe_rw15_cp_times[1])
    output_data['Encrypt (ms)'].append(maabe_rw15_cp_times[2])
    output_data['Decrypt (ms)'].append(maabe_rw15_cp_times[3])
    output_data['Ciphertext size (bytes)'].append(maabe_rw15_cp_times[16])
    #
    maabe_yj14_cp = MAABE(pairing_group)
    maabe_yj14_cp_times = measure_average_times(maabe_yj14_cp, attr_list, policy_str, k1, k2, k3, msg)
    print_running_time(maabe_yj14_cp.name, maabe_yj14_cp_times, len(attr_list))
    print('{:<26}'.format('   | authority setup ') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(maabe_yj14_cp_times[12] * 1000, '7.2f') + '          -' + '        -  ' + format(' ') + '  ' + format(
        '  ') + ' - ' + format(
        ' '))
    print('{:<26}'.format('   | user registration ') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(maabe_yj14_cp_times[13] * 1000, '7.2f') + '          -' + '        -  ' + format(' ') + '  ' + format(
        '  ') + ' - ' + format(
        ' '))
    print('{:<26}'.format('   | cph_size (bytes)') + str(len(attr_list)).format(' ') + '{:<9}'.format(
        '') + '      -    ' +
          '      -' + format(' ') + '  ' + format(maabe_yj14_cp_times[17], '5.1f') + format(''))
    #
    output_data['Scheme'].append(maabe_yj14_cp.name)
    output_data['#attributes'].append(len(attr_list))
    output_data['Setup (ms)'].append(maabe_yj14_cp_times[0])
    output_data['Keygen (ms)'].append(maabe_yj14_cp_times[1])
    output_data['Encrypt (ms)'].append(maabe_yj14_cp_times[2])
    output_data['Decrypt (ms)'].append(maabe_yj14_cp_times[3])
    output_data['Ciphertext size (bytes)'].append(maabe_yj14_cp_times[17])
    #
    easyabe23_cp = easyabe23cp(pairing_group, attr_list)
    easyabe23_cp_times = measure_average_times(easyabe23_cp, attr_list, policy_str, k1, k2, k3, msg)
    print_running_time(easyabe23_cp.name, easyabe23_cp_times, len(attr_list))
    print('{:<26}'.format('   | cph_size (bytes)') + str(len(attr_list)).format(' ') + '{:<9}'.format(
        '') + '      -    ' +
          '      -' + format(' ') + '  ' + format(easyabe23_cp_times[20], '5.1f') + format(''))
    print('-' * 80)
    #
    output_data['Scheme'].append(easyabe23_cp.name)
    output_data['#attributes'].append(len(attr_list))
    output_data['Setup (ms)'].append(easyabe23_cp_times[0])
    output_data['Keygen (ms)'].append(easyabe23_cp_times[1])
    output_data['Encrypt (ms)'].append(easyabe23_cp_times[2])
    output_data['Decrypt (ms)'].append(easyabe23_cp_times[3])
    output_data['Ciphertext size (bytes)'].append(easyabe23_cp_times[20])

    fabeo22_cp = FABEO22CPABE(pairing_group)
    fabeo22_cp_times = measure_average_times(fabeo22_cp, attr_list, policy_str, k1, k2, k3, msg)
    print_running_time(fabeo22_cp.name, fabeo22_cp_times, len(attr_list))
    print('{:<26}'.format('   | cph_size (bytes)') + str(len(attr_list)).format(' ') + '{:<9}'.format(
        '') + '      -    ' +
          '      -' + format(' ') + '  ' + format(fabeo22_cp_times[19], '5.1f') + format(''))
    print('-' * 80)
    #
    output_data['Scheme'].append(fabeo22_cp.name)
    output_data['#attributes'].append(len(attr_list))
    output_data['Setup (ms)'].append(fabeo22_cp_times[0])
    output_data['Keygen (ms)'].append(fabeo22_cp_times[1])
    output_data['Encrypt (ms)'].append(fabeo22_cp_times[2])
    output_data['Decrypt (ms)'].append(fabeo22_cp_times[3])
    output_data['Ciphertext size (bytes)'].append(fabeo22_cp_times[19])


# get parameters of the monotone span program
def get_par(pairing_group, policy_str, attr_list):
    msp_obj = MSP(pairing_group)
    policy = msp_obj.createPolicy(policy_str)
    mono_span_prog = msp_obj.convert_policy_to_msp(policy)
    nodes = msp_obj.prune(policy, attr_list)

    n1 = len(mono_span_prog)  # number of rows
    n2 = msp_obj.len_longest_row  # number of columns
    m = len(attr_list)  # number of attributes
    i = len(nodes)  # number of attributes in decryption

    return n1, n2, m, i


# create policy string and attribute list for a boolean formula of the form "1 and 2 and 3"
def create_policy_string_and_attribute_list(n, pairing_group):
    policy_string = '(1'
    attr_list = ['1']
    # we process the hidden access policy
    fahdabe_instance = FAHDABE24MAABE_CP(pairing_group)
    default_hidden_value = fahdabe_instance.hide_string_with_epsilon(string_to_hide='1', epsilon='epsilon')
    hidden_policy_string = '(' + str(default_hidden_value)
    # we process the policy for Rouselakis-Waters
    rw_policy_string = '(1@AA1'
    rw_attr_list = ['1@AA1']
    AA_list = ['AA1', 'AA2', 'AA3']

    for i in range(2, n + 1):
        policy_string += ' and ' + str(i)  # {i}'
        attr1 = str(i)  # f'{i}'
        attr_list.append(attr1)
        #
        current_attribute = fahdabe_instance.hide_string_with_epsilon(string_to_hide=str(i), epsilon='epsilon')
        hidden_policy_string += ' and ' + str(current_attribute)
        #
        attr1 = str(i) + '@' + random.choice(AA_list)
        rw_attr_list.append(attr1)
        rw_policy_string += ' and ' + attr1

    policy_string += ')'
    hidden_policy_string += ')'
    rw_policy_string += ')'

    # attr_list = ['ONE', 'TWO', 'FOUR']

    return policy_string, attr_list, hidden_policy_string, rw_policy_string, rw_attr_list


def main():
    # instantiate a bilinear pairing map
    # pairing_group = PairingGroup('MNT159')
    # pairing_group = PairingGroup('MNT224')
    pairing_group = PairingGroup('SS512')

    msg = pairing_group.random(GT)

    # for 'KANYANG-XIAOHUAJIA' we suppose msg = msg1 || msg2 || msg3
    # we generate three content keys to realize E(k_i, m_i)
    k1 = pairing_group.random(GT)
    k2 = pairing_group.random(GT)
    k3 = pairing_group.random(GT)

    policy_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    # policy_size = 1
    #
    # policy_str, attr_list, hidden_policy = create_policy_string_and_attribute_list(policy_size, pairing_group)
    # run_all(pairing_group, policy_size, policy_str, attr_list, hidden_policy, msg)

    for policy_size in policy_sizes:
        policy_str, attr_list, hidden_policy, rw_policy_string, rw_attr_list = create_policy_string_and_attribute_list(
            policy_size, pairing_group)
        run_all(pairing_group, policy_size, policy_str, attr_list, hidden_policy, rw_policy_string, rw_attr_list, k1,
                k2, k3, msg)

    # we write data to files
    df1 = pd.DataFrame(output_data)
    df2 = pd.DataFrame(fahdabe_cph_data)

    df1.to_csv('output_data.csv')
    df2.to_csv('fahdabe_cph_data.csv')


if __name__ == "__main__":
    debug = True
    main()
