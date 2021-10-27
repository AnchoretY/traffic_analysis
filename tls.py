'''
Author: AnchoretY
Date: 2021-10-27 10:27:13
LastEditors: AnchoretY
LastEditTime: 2021-10-27 10:37:32
'''

import os

import pandas as pd
import numpy as np
from joblib import Parallel,delayed


def pas:
    pass


def tls_parsing(input_file, output_path="./data/dns_output/"):
    '''
    description: 
    param {*}
    return {*}
    '''
    tmp_path = "./data/dns_tmp/"
    output_path = "./data/dns_output/"

    filename = input_file.split("/")[-1].split(".")[0]
    tmp_file = os.path.join(tmp_path, filename+".csv")
    output_file = os.path.join(output_path, filename+".csv")
    # parsing_string = "tshark -r {}  -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e frame.len \
    #     -e eth.src -e eth.dst -e udp.srcport -e udp.dstport -e dns.id -e dns.flags.response -e dns.flags.opcode -e dns.flags.authoritative \
    #     -e dns.flags.truncated -e dns.flags.recdesired -e dns.flags.recavail -e dns.flags.authenticated -e dns.flags.checkdisable \
    #     -e dns.flags.rcode -e dns.count.queries -e dns.count.answers -e dns.count.auth_rr -e dns.count.add_rr -e dns.qry.name \
    #     -e dns.qry.type -e dns.qry.class -e dns.resp.name -e dns.resp.type -e dns.resp.ttl -e dns.resp.z.do \
    #     -E separator=\",\" -E aggregator=\" \" -E header=y -E occurrence=f -E quote=d > {}".format(input_file, output_file)

    # --------------- pcap解析 -----------------------------
    parsing_string = "tshark -r {}  -Y \"dns.qry.name contains 2bb0a7b2.ns2.ssltestdomain.xyz||dns.qry.name contains 2bb0a7b2.ns1.ssltestdomain.xyz\" \
        -T fields -e frame.number -e frame.time_delta_displayed -e ip.src -e ip.dst \
        -e udp.srcport -e udp.dstport -e frame.len -e dns.id -e dns.flags.response -e dns.flags.opcode -e dns.qry.name \
        -e dns.qry.type -e dns.a -e dns.txt -e dns.txt.length -e dns.flags.rcode\
        -E separator=\",\" -E aggregator=\" \" -E header=y -E occurrence=f -E quote=d > {}".format(input_file, tmp_file)
    tshark_flag = os.system(parsing_string)

    if tshark_flag==0:
        print("{} analysis success!tmp file save to {}".format(input_file,tmp_file))
    else:
        print("sorry, {} analysis fail!")