# Python implementation of the LtHash hash function

Researchers from Facebook recently ([paper](https://eprint.iacr.org/2019/227.pdf)) implemented LtHash, initially proposed by [Bellare and Micciancio](https://link.springer.com/content/pdf/10.1007%2F3-540-69053-0_13.pdf).

The feature thath makes LtHash special is _set homomorphism_. It means that for any sets _A_, _B_, we have 

_H(A u B)=H(A)+H(B)_,

where by _A u B_ we mean set union.

The python script uses the [PyCrypto](https://pycryptodome.readthedocs.io/en/latest/src/installation.html) library to run SHAKE128, the eXtendable Output Function from the SHA3 standard.

In the demo.py there is an example of how to use the package and what does set homomorphism means in practice.
