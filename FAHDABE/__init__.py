'''
Authors: Arthur Sandor Voundi Koe, Wei Jian Hong, Jin Li, Chen Xiao Feng

| From: "Fully Adaptive and Policy-Hiding Decentralized Ciphertext-Policy Attribute Based Encryption".
| Published in: 2025
| Available from:
| Notes:
| Security Assumption:
|
| type:           Multi-authority ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Code authors:    Arthur Sandor Voundi Koe
:Date:            12/2024
'''


import ast

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from LThash.lthash import LtHash

# We allow the debugging mode
debug = True

# type annotations
pk_t = {'g': G1, 'g2': G2, 'h': G1, 'f': G1, 'e_gg_alpha': GT}
mk_t = {'beta': ZR, 'g2_alpha': G2}
do_key_t = {'sk_1': G2, 'hk_1': G2, 'hk_2': G2, 'h_epsilon': str, 'd_attd': G2, 't_attd': G1, 'h_attd': str}
aa_key_t = {'D_j': G2, 'T_j': G1}
rrd_key_t = dict(aa_key_t)
du_key_t = {'sk': do_key_t, 'hk': rrd_key_t}
du_hkey_t = {
    'hk_1': do_key_t['hk_1'], 'hk_2': do_key_t['hk_2'], 'h_epsilon': do_key_t['h_epsilon'],
    'd_attd': do_key_t['d_attd'], 't_attd': do_key_t['t_attd'], 'h_attd': do_key_t['h_attd'],
    'rrd_key': du_key_t['hk']
}
ct_do_t = {'policy': str, 'cs': GT, 'c': G1, 'c_attd': G2, 'cp_attd': G1, 'witness': GT}
ct_rrd_t = {
    'cs_rrd': GT, 'cs_do': GT, 'c_do': G1, 'c_rrd': G1, 'c_attd': G2, 'cp_attd': G1, 'witness': GT,
    'policy': str, 'C_y': G1, 'C_y_pr': G2
}

'''
 FAHDABE Main Class
'''


class FAHDABE24MAABE_CP(ABEnc):

    def __init__(self, group_obj):
        ABEnc.__init__(self)
        self.name = "FAHDABE MA-CP-ABE"
        self.crs = {}
        self.util = SecretUtil(group_obj, verbose=True)
        self.group = group_obj

        # we pick random generator
        self.g = self.group.random(G1)

        # parameters of H2 (LThash)
        self.lattice_dimension = 8
        self.lattice_degree = 10

    '''
    Utility functions for LThash
    '''

    def add_data_to_hash(self, input1_LThash, input2):
        # All data inputs have to be sets
        set_input2 = {input2}
        # we define a lthash3 object to compute digest
        lthash3 = LtHash(self.lattice_dimension, self.lattice_degree)
        # we need to set the digest of lthash3 to be input1
        # we use ast to recover the list (hash digest is a list)
        input1_list = ast.literal_eval(input1_LThash)
        # we define a novel lthash object to add our string digest
        # lthash3.digest = input1_list
        lthash_input1 = LtHash(self.lattice_dimension, self.lattice_degree)
        lthash_input1.digest = input1_list
        # print("lthash_input1 digest output value is ", lthash_input1.digest)
        # We first add the the value of lthash_input1
        lthash3.add(lthash_input1)
        # print("lthash3_digest current output value is ", lthash3.digest)
        # We compute LThash(input2) to realize H2(input1) + H2(input2)
        lthash_input2 = LtHash(self.lattice_dimension, self.lattice_degree)
        lthash_input2.eval(set_input2)
        lthash3.add(lthash_input2)
        # -------------------------------------------------------------------
        # We Work the output
        # -------------------------------------------------------------------
        output = lthash3.digest
        # We use map and join conjointly
        mapped_output = map(str, output)
        # we convert the output into a string separated by space (space is used in ABE to separate attributes of the access policy so no space)
        output = ",".join(mapped_output)  # " ".join(str(element) for element in output )
        # we will insert "[" and "]" to the list to have a string expression of the list
        left_brackect = '['
        right_bracket = ']'
        output = f"{left_brackect}{output}{right_bracket}"
        # we process the output before outputting the result
        output = output.strip()  # .encode()
        # we return the output
        return output

    def lthash_compute(self, input1):
        set_input1 = {input1}
        # New Hash object
        lthash1 = LtHash(self.lattice_dimension, self.lattice_degree)
        lthash1.eval(set_input1)
        # --------------------------------------------------------------------------------------------
        # we process the output
        output = lthash1.digest
        # We use map and join conjointly
        mapped_output = map(str, output)
        # we convert the output into a string separated by space (space is used in ABE to separate attributes of the access policy so no space)
        output = ",".join(mapped_output)  # " ".join(str(element) for element in output )
        # we will insert "[" and "]" to the list so as to have a string expression of the list
        left_bracket = '['
        right_bracket = ']'
        output = f"{left_bracket}{output}{right_bracket}"
        # we process the output before outputting the result
        output = output.strip()  # .encode()
        return output

    def lthash_add_values(self, input1, input2):
        # -------------------------------------------------------------------------
        # Hash object
        lthash1 = LtHash(self.lattice_dimension, self.lattice_degree)
        set_input1 = {input1}
        lthash1.eval({input1})
        lthash2 = LtHash(self.lattice_dimension, self.lattice_degree)
        set_input2 = {input2}
        lthash2.eval({input2})
        # Hash of the union of the data
        lthash3 = LtHash(self.lattice_dimension, self.lattice_degree)
        lthash3.eval(set_input1.union(set_input2))
        lthash1.add(lthash2)
        if lthash3.digest != lthash1.digest:
            print("None")
        # return None
        else:
            # ------------------------------------------
            # We precess the output of the data
            # ------------------------------------------
            output = lthash1.digest
            # We use map and join conjointly
            mapped_output = map(str, output)
            # we convert the output into a string separated by space (space is used in ABE to separate attributes of the access policy so no space)
            output = ",".join(mapped_output)  # " ".join(str(element) for element in output )
            # we will insert "[" and "]" to the list so as to have a string expression of the list
            left_brackect = '['
            right_bracket = ']'
            output = f"{left_brackect}{output}{right_bracket}"
            # we process the output before outputting the result
            output = output.strip()  # .encode()
            return output

    def setup(self) -> (pk_t, mk_t):
        g = self.group.random(G1)
        gp = self.group.random(G2)
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)

        # initialize pre-processing for generators
        g.initPP()
        gp.initPP()
        h = g ** beta
        f = gp ** ~beta
        e_gg_alpha = pair(g, gp ** alpha)
        pk = {'g1': g, 'g2': gp, 'h': h, 'f': f, 'e_gg_alpha': e_gg_alpha}
        mk = {'beta': beta, 'g_alpha': gp ** alpha}
        return pk, mk

    def keygen0(self, epsilon: str) -> str:
        return self.lthash_compute(epsilon)

    def hide_string_with_epsilon(self, string_to_hide: str, epsilon: str) -> str:
        return self.lthash_add_values(epsilon, string_to_hide)

    def keygen1(self, pp: pk_t, msk: mk_t, gid: str, epsilon: str, attd: str) -> do_key_t:
        """
           @sk_1 = kept secret by user
           @hk_1 = helper key used in ciphertext decryption
           @hk_2 = helper key used to blind attribute authority secret keys
           @h_epsilon = blinded value of the epsilon string set by DO
           @h_attd = blinded value of the dummy attribute attd
           @d_attd = helper key used during decryption by the cloud to compute e(g,g) ** (r * s_2)
           @t_attd = helper key used during decryption by the cloud to compute e(g,g) ** (r * s_2)
        """
        # generate random exponents
        r, rp = self.group.random(), self.group.random()
        gamma = self.group.hash(str(gid), ZR)
        # generate terms for the data owner secret key part
        g_r = (pp['g2'] ** r)
        sk_1 = (msk['g_alpha'] * g_r) ** (1 / msk['beta'])
        hk_1 = pp['g2'] ** (gamma / msk['beta'])
        hk_2 = pp['g2'] ** (r + gamma)
        h_attd = self.lthash_add_values(epsilon, attd)
        # lthash1 = LtHash(self.lattice_dimension, self.lattice_degree)
        # lthash1.eval(epsilon)
        h_epsilon = self.lthash_compute(epsilon)
        # h_attd = lthash1.add_data(attd)
        attd_hidden_element = self.group.hash(str(h_attd), ZR)
        d_attd = hk_2 * ((pp['g2'] ** attd_hidden_element) ** rp)
        t_attd = pp['g1'] ** rp

        do_key = {
            'sk_1': sk_1, 'hk_1': hk_1, 'hk_2': hk_2, 'h_epsilon': h_epsilon, 'd_attd': d_attd,
            't_attd': t_attd, 'h_attd': h_attd
        }

        return do_key

    def hide(self, do_key: do_key_t, S: list) -> list:

        """
        :param do_key: DO secret key part
        :param S: set of user attributes (set of unhidden attributes)
        :return: the set of hidden attributes as a list
        """
        S_hidden = []
        for j in S:
            instance_lthash = self.add_data_to_hash(do_key['h_epsilon'], j)
            S_hidden.append(instance_lthash)
        return S_hidden

    def keygen2(self, pp: pk_t, S_hidden: list, hash_gid) -> aa_key_t:
        """
        :param pp: public parameters
        :param S_hidden: Set of hidden user attributes
        :param hash_gid: hash-to-scalar value of the user gid
        :return: Attribute authority secret key (for a single AA)
        """
        # for the purpose of comparison with related work, the gid could be directly provided as parameter
        if type(hash_gid) is str:
            hash_gid = self.group.hash(str(hash_gid), type=ZR)

        AA_key = {}
        for j in S_hidden:
            # print("the current attribute being processed in keygen2 is ", j, "\n")
            r_j = self.group.random()
            attr_hidden_element = self.group.hash(str(j), ZR)
            D_j = (((pp['g2'] ** attr_hidden_element) ** r_j) * (
                    (pp['g2'] ** attr_hidden_element) ** (r_j * hash_gid)))  # self.group.hash(j, G2) ** r_j)
            T_j = ((pp['g2'] ** r_j) * (pp['g2'] ** (r_j * hash_gid)))
            AA_key[j] = {'D_j': D_j, 'T_j': T_j}
        return AA_key

    def keygen3(self, aa_key_list: [aa_key_t]) -> rrd_key_t:
        rrd_key = {}
        # complete set of hidden attributes fo Data user
        S_hidden = list()
        for aa_key in aa_key_list:
            for j in list(aa_key.keys()):
                rrd_key[j] = aa_key[j]
                S_hidden.append(j)
        rrd_key['S_hidden'] = S_hidden
        return rrd_key

    def keygen4(self, do_key: do_key_t, rrd_key: rrd_key_t) -> (du_key_t, du_hkey_t):
        DU_key = {'sk': do_key, 'hk': rrd_key}
        DU_hkey = {
            'hk_1': do_key['hk_1'], 'hk_2': do_key['hk_2'], 'h_epsilon': do_key['h_epsilon'],
            'd_attd': do_key['d_attd'], 't_attd': do_key['t_attd'], 'h_attd': do_key['h_attd'],
            'rrd_key': rrd_key, 'S_hidden': rrd_key['S_hidden']
        }
        return DU_key, DU_hkey

    def encrypt1(self, pp: pk_t, M: GT, policy_str: str, epsilon: str, attd: str) -> ct_do_t:
        # the policy needs to be preprocessed such that all attributes are hidden
        # prior to calling encrypt1
        # our  shared secret on the dummy sub-tree ( or dummy attribute)
        s_2 = self.group.random()
        cs = M * (pp['e_gg_alpha'] ** s_2)
        c = pp['h'] ** s_2
        hidden_attd = self.lthash_add_values(epsilon, attd)

        hidden_attd_element = self.group.hash(str(hidden_attd), ZR)
        #
        c_attd = ((pp['g2'] ** hidden_attd_element) ** s_2)
        cp_attd = pp['g1'] ** s_2
        #
        # computation of the witness
        witness_term = cs * (pp['e_gg_alpha'] ** s_2)
        str_from_pair = self.group.hash(str(witness_term))
        witness_commitment = self.group.hash(str(str_from_pair), type=ZR)
        witness = cs ** (1 / witness_commitment)
        #
        ct_do = {'policy': policy_str, 'cs': cs, 'c': c, 'c_attd': c_attd, 'cp_attd': cp_attd, 'witness': witness}
        return ct_do

    def encrypt2(self, pp: pk_t, ct_do: ct_do_t) -> ct_rrd_t:
        ct_rrd: ct_rrd_t = {}
        s_1 = self.group.random()
        ct_rrd['cs_rrd'] = ct_do['cs'] * (pp['e_gg_alpha'] ** s_1)
        ct_rrd['cs_do'] = ct_do['cs']
        ct_rrd['c_do'] = ct_do['c']
        ct_rrd['c_rrd'] = pp['h'] ** s_1
        ct_rrd['c_attd'] = ct_do['c_attd']
        ct_rrd['cp_attd'] = ct_do['cp_attd']
        ct_rrd['witness'] = ct_do['witness']
        ct_rrd['policy'] = ct_do['policy']
        #
        # we process the policy
        policy = self.util.createPolicy(ct_rrd['policy'])
        a_list = self.util.getAttributeList(policy)
        shares = self.util.calculateSharesDict(s_1, policy)
        #
        C_y, C_y_pr = {}, {}
        for i in shares.keys():
            j = self.util.strip_index(i)
            C_y[i] = pp['g1'] ** shares[i]
            attr_hidden_element = self.group.hash(str(j), ZR)
            C_y_pr[i] = (pp['g1'] ** attr_hidden_element) ** shares[i]
        ct_rrd['C_y'] = C_y
        ct_rrd['C_y_pr'] = C_y_pr
        return ct_rrd

    def transform(self, ct_rrd: ct_rrd_t, du_hkey: du_hkey_t) -> GT:
        #
        policy = self.util.createPolicy(ct_rrd['policy'])
        pruned_list = self.util.prune(policy, du_hkey['S_hidden'])

        #
        if not pruned_list:
            print("Access policy in FAHDABE unsatisfied ! \n")
            TC = None
            helper_decryption_term = None
            ct_do_pr = None
            return TC, helper_decryption_term, ct_do_pr

        z = self.util.getCoefficients(policy)
        TC = 1
        for i in pruned_list:
            j = i.getAttributeAndIndex()
            k = i.getAttribute()
            TC *= (pair(ct_rrd['C_y'][j], (du_hkey['hk_2'] * du_hkey['rrd_key'][k]['D_j'])) / pair(ct_rrd['C_y_pr'][j], du_hkey['rrd_key'][k]['T_j'])) ** z[j]

        # performing helper computations to help DU decrypt
        helper_term1 = pair(ct_rrd['cp_attd'], du_hkey['d_attd'])
        helper_term2 = pair(du_hkey['t_attd'], ct_rrd['c_attd'])
        helper_term3 = helper_term1 / helper_term2  # e(g,g) ** (r * s2) * e(g,g) ** (gamma * s2)
        helper_term4 = pair(ct_rrd['c_do'], du_hkey['hk_1'])
        helper_decryption_term = helper_term3 / helper_term4  # e(g,g) ** (r * s2)
        #
        ct_do_pr = {
            'policy': ct_rrd_t['policy'], 'cs': ct_rrd['cs_do'], 'c': ct_rrd['c_do'],
            'c_attd': ct_rrd['c_attd'], 'cp_attd': ct_rrd['cp_attd'], 'witness': ct_rrd['witness']
        }
        #
        return TC, helper_decryption_term, ct_do_pr

    def udecrypt(self, TC: GT, helper_decryption_term: GT, ct_do_pr: ct_do_t, du_key: du_key_t) -> GT:
        if ct_do_pr is None or TC is None or helper_decryption_term is None:
            print("impossible to decrypt \n")
            return False

        do_key = du_key['sk']
        F = pair(ct_do_pr['c'], do_key['sk_1'])  # e(g,g) ** (alpha * s2) * e(g,g) ** (r * s2)
        I = F / helper_decryption_term
        #
        # checking the witness value
        witness_term = ct_do_pr['cs'] * I
        str_from_pair = self.group.hash(str(witness_term))
        witness_commitment = self.group.hash(str(str_from_pair), type=ZR)
        witness = ct_do_pr['cs'] ** (1 / witness_commitment)
        #
        if witness != ct_do_pr['witness']:
            print(" Fail to pass the witness verification process \n")
            return False
        #
        return ct_do_pr['cs'] / I

