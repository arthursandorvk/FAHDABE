FROM ubuntu:18.04

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

ENV LIBRARY_PATH /usr/local/lib
ENV LD_LIBRARY_PATH /usr/local/lib

RUN    apt update \
    && apt upgrade -y \
    && apt install -y locales

WORKDIR /root

RUN    apt install -y wget python python-pip
RUN    apt install -y gcc flex bison build-essential
RUN    apt install -y m4 gawk
RUN    apt install -y python3-setuptools


# download and set up zlib, libffi, gmp  and pbc
RUN    wget http://zlib.net/zlib-1.3.1.tar.gz
RUN    wget https://github.com/libffi/libffi/releases/download/v3.4.5/libffi-3.4.5.tar.gz
RUN    wget https://ftp.gnu.org/gnu/glibc/glibc-2.38.tar.gz
RUN    wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz
RUN    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
RUN    wget https://www.openssl.org/source/openssl-3.0.13.tar.gz


RUN    tar -xzf zlib-1.3.1.tar.gz
RUN    tar -xzf libffi-3.4.5.tar.gz 
RUN    tar -xzf glibc-2.38.tar.gz
RUN    tar -xf gmp-6.3.0.tar.xz
RUN    tar -xzf pbc-0.5.14.tar.gz


RUN    cd zlib-1.3.1 \
    && ./configure \
    && make \
    && make install \
    && cd ..

RUN    cd libffi-3.4.5 \
    && ./configure \
    && make \
    && make install \
    && cd ..


RUN    cd glibc-2.38/
RUN    mkdir glibc-build/
RUN    cd glibc-build/
RUN    /root/glibc-2.38/configure --prefix=/root/glibc-2.38/glibc-build/ \
    && make \
    && make install \
    && cd .. \
    && cd ..

RUN    cd gmp-6.3.0 \
    && ./configure \
    && make \
    && make install \
    && cd ..

RUN    cd pbc-0.5.14 \
    && ./configure \
    && make \
    && make install \
    && cd ..

# install packages
RUN    apt install -y libssl-dev
RUN    apt install -y libglib2.0-dev
RUN    apt install -y git

#--------------------------------------
#---------User configuration-----------
#--------------------------------------

# install sudo package
#RUN apt install -y sudo

# Setting a non-root user
#RUN useradd -m fahdabeUser
#RUN usermod -aG sudo fahdabeUser

# Switch to the non-root user
#USER fahdabeUser
#USER root


# Set the working directory of the new user
#WORKDIR /home/fahdabeUser

# download and set up FAHDABE
RUN    git clone https://arthursandorvk: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@github.com/arthursandorvk/FAHDABE.git

RUN    cd FAHDABE \
    && ls \
    # inside FAHDABE dir, set up the LTHASH project
    && git clone https://github.com/czajkowskijan/lthash-python.git \
    #copy fahdabe helper classes into the LTHASH project directory
    && ls \
    && cd Utility_FAHDABE \
    && cp ./* ../lthash-python/ \
    && cd ..

# changing the shell
#RUN chmod 774 -R /usr/*
#RUN ls -al /root/FAHDABE/libbswabe-0.9_FAHDABE/
#RUN chmod 774 /root/FAHDABE/libbswabe-0.9_FAHDABE/*
#RUN chmod 774 /root/FAHDABE/cpabe-0.11_FAHDABE/*
RUN chmod 774 -R /root/FAHDABE/


# configuring FAHDABE project
RUN    cd FAHDABE \
    && cd libbswabe-0.9_FAHDABE \
    && make clean \
    && make \
    && make install \
    #&& ldconfig \
    && cd .. \
    && cd cpabe-0.11_FAHDABE \
    # && make #CFLAGS="-Wno-error=format-truncation" \
    && make clean \
    && make \
    && make install \
        #&& ldconfig \
    && cd ..


RUN pwd
RUN ls -al FAHDABE/lthash-python/
RUN apt install -y python3 python3-pip

#had an timeout issue installing pycryptodome from main repository
RUN pip3 install pycryptodome
RUN pip3 install pycrypto
#RUN pip install pycryptodomex
#RUN python3 -m pip install --upgrade pip

RUN  echo -e "lthash of the words epsilon !---> \n"
RUN python3 FAHDABE/lthash-python/fahdabe-lthash-compute.py epsilon
RUN apt install -y locate
RUN locate mkinstalldirs 

# https://developer-old.gnome.org/glib/stable/glib-running.html
RUN export G_SLICE=always-malloc 

# defining some ENV variables

# value of the attribute masking factor epsilon (any string can be used)
ENV epsilon "epsilon_hide"

# value of the dummy attribute dummy (any string can be used)
ENV dummy "dummy_attr"

# value of the public key file name (hardcoded)
ENV publicKey "pub_key"

# value of the master key file name (hardcoded)
ENV masterKey "master_key"

# number of attribute authorities
ENV AANum 3

# value of File name hosting the Data Owner key
ENV doKey "DO_key" 

# user attributes sets where each set is managed by a different Attribute authority
ENV userAttr1 "A B"
ENV userAttr2 "C D"
ENV userAttr3 "E F hired"

# corresponding file names to contain the set of hidden attributes
ENV hiddenAttrFile1 "A1"
ENV hiddenAttrFile2 "A2"
ENV hiddenAttrFile3 "A3"

# File names to contain the Attribute autority secret keys per set of hidden attributes
ENV AAFile1 "AA1_key"
ENV AAFile2 "AA2_key"
ENV AAFile3 "AA3_key"

# File name to contain the resource-rich device key (aggregation of AA secret keys)
ENV rrdKeyFile "rrd_key"

# File name to contain the complete user secret key file
ENV userKeyFile "user_key"

# File name to contain the public subpart of the complete user secret key (hardcoded)
ENV publicUserSubKeyFile "DU_Out_key"

# the access policy in the scheme
ENV accessPolicy "A and (B or C) and (hire_date or 876868)"

# File name to contain the plaintext
ENV plaintextFile "fahdabe.txt"

# File name to contain the second stage ciphertext produced by the Resource Rich Device
ENV rrdCiphertextFile "fahdabe.txt.ct_do.cpabe"

# File name to contain the intermediate decryption results
ENV decryptResultFile "decryption_results"

# File name to contain the intermediate decryption results from first ciphertext transformation
ENV intermediateCiphertextFile "fahdabe.txt.ct_do"

# File name to contain the final decrypted content after final transformation on the user premises
ENV decryptedContentFile "fahdabe_decrypted.txt"

# File name to contain the attribute blinding parameter sent by the DO
ENV du_blindFile "du_blind"

# temporary file to allow python and C to communicate over H2 computations
ENV tempFile "tempFahdabe.txt"

# the file where DO stores the structure that relates to epsilon attribute blinding parameter
ENV epsilon_DO_paramFile "epsilon_DO_param"
 

# running FAHDABE

RUN FAHDABE/fahdabe_run.sh
#CMD ["/root/FAHDABE/fahdabe_run.sh"]
