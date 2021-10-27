'''
Author: your name
Date: 2021-10-25 15:48:56
LastEditTime: 2021-10-26 20:12:15
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: /traffic_analysis/dns.py
'''
import os

import pandas as pd
import numpy as np
from joblib import Parallel,delayed


def dns_parsing(input_file, output_path="./data/dns_output/"):
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

    # -------------- qry type可读化 -----------------------
    df = pd.read_csv(tmp_file)
    qry_type_dict = {
        1:"A",
        2:"NS",
        5:"CNAME",
        6:"SOA",
        12:"PTR",
        13:"HINFO",
        15:"MX",
        16:"TXT",
        28:"AAAA",
        47:"NSEC",
        50:"NSEC3"
    }

    df["dns.qry.type"] = df["dns.qry.type"].apply(lambda x:qry_type_dict[x])

    # ---------------- 合并请求与响应 --------------------------------
    df_query = df[df["dns.flags.response"]==0]
    df_query = df_query.drop(["dns.a","dns.txt","dns.txt.length","frame.number","dns.flags.response","dns.flags.rcode"],axis=1)

    df_response = df[df["dns.flags.response"]==1]
    df_response = df_response.rename(columns={
        "ip.src":"ip.dst",
        "ip.dst":"ip.src",
        "udp.srcport":"udp.dstport",
        "udp.dstport":"udp.srcport",
        "frame.time_relative":"response_time",
        "frame.len":"response.frame.len"
    })

    df_response = df_response.drop(["dns.flags.opcode","dns.qry.name","dns.qry.type","dns.flags.response","dns.flags.opcode","frame.number","frame.time_delta_displayed"],axis=1)
    df_result = pd.merge(df_query,df_response,on=["ip.dst","ip.src","udp.dstport","udp.srcport","dns.id"],how='left')
    df_result = df_result.drop(["dns.id"],axis=1)

    df_result.to_csv(output_file,index=False)
    
    print("Completed Conversation merge！")
    print("Extract {} http info to{}!".format(input_file,output_file))


    return df_result


def floder_pcap_analysis_dns(path,n_jobs=5):
    """
        对整个文件夹中的pcap文件中http流量进行多进程解析
        Parameters:
        --------------------------
            path: pcap文件存储路径
            n_jobs: 进程数
    """
    filename_l = os.listdir(path)
    file_l = []
    for filename in filename_l:
        if filename[0]!=".":
            file = os.path.join(path,filename)
            file_l.append(file)

    Parallel(n_jobs=n_jobs)(delayed(dns_parsing)(file) for file in file_l)

dns_parsing("/Volumes/PassPort/DataCon/datacon2021/网络流量分析/datacon2021_traffic_cs2_dns/dns.pcap")

floder_pcap_analysis_dns("/Volumes/PassPort/DataCon/datacon2021/网络流量分析/datacon2021_traffic_cs2_dns/dns_sample/")