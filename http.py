'''
Author: your name
Date: 2021-10-21 18:31:07
LastEditTime: 2021-10-24 17:40:44
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: /traffic_analysis/http.py
'''

import os
import pandas as pd
from joblib import Parallel,delayed

def http_pcap2csv(input_file):
    """
        将单个pcap包中的HTTP流量进行解析。
        解析思路为：首先将pcap流量中的HTTP请求进行解析，提取全部关键字并标明该条数据是response还是request，然后根据然后使用
            request数据的src_ip、dst_ip、src_port、dst_port、nxtseq与response数据的dst_ip、src_ip、dst_port、src_port、ack进
            行匹配，匹配成功的数据则合并为一条完整的请求响应报文。
        Request报文中使用的字段：
            src_ip：源IP
            dst_ip：目的IP
            src_port: 源端口
            dst_port：目的端口
            host：主机
            uri： 统一资源定位符
            method：请求方法
            user_agent：客户端代理值
            cookie：cookie值
            referer：页面跳转的源头
            
        Response报文中使用的字段：
            response_code： 响应码
            content_type： 相应文件类型
            content_length： 相应报文长度         
        
        Parameters:
        -------------------------------------------
            input_fille: 要进行解析的文件名。
              
        
    """
    tmp_path = "./data/tmp/"
    output_path = "./data/output/"
    
    input_file_name = input_file.split("/")[-1].split(".")[0]
    tmp_file = "{}{}.csv".format(tmp_path,input_file_name)
    output_file = "{}{}.csv".format(output_path,input_file_name)
    
    if not os.path.exists(tmp_path):
        os.makedirs(tmp_path)
    
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    
    
    # 使用tshark进行pcap包解析
    print("Start {} http traffic analysis...".format(input_file))
    tshark_flag = os.system(
        "tshark -r {} -Y http  -T fields -e http.response -e frame.number -e frame.time_relative -e ip.src -e ip.dst  -e tcp.srcport -e tcp.dstport \
        -e tcp.nxtseq -e tcp.ack  -e http.host -e http.request.uri  -e http.request.method \
        -e http.content_type -e http.content_length -e frame.len -e http.cookie -e http.referer -e http.user_agent -e http.response.code -e http.file_data -e http.date \
        -E separator=\"\t\" -E aggregator=\" \" -E header=y  -E occurrence=f -E quote=d > {}".format(input_file,tmp_file)
    )
    
    if tshark_flag==0:
        print("{} analysis success!tmp file save to {}".format(input_file,tmp_file))
    else:
        print("sorry, {} analysis fail!")
    
    # 请求包响应包合并成一个会话
    print("Start merge requerst and response to a Conversation...")
    df = pd.read_csv(open(tmp_file,errors='ignore'),on_bad_lines='skip',encoding='utf-8',sep='\t')

    # 获取请求报文
    df_request = df[df["http.response"].isna()]
    df_request = df_request.drop(axis=1,columns=['http.response','tcp.ack','http.response.code','http.content_type','http.content_length'])
    df_request = df_request.rename(columns={
        "http.file_data":"http.post_body",
        "frame.time_relative":"request_time",
        "frame.len":"frame.request_len"
    })

    # 获取响应报文，srcip、dstip、srcport、dstport对换，tcp.ack换成tcp.nxtseq，准备与请求进行匹配
    df_response = df[~df["http.response"].isna()][["ip.src","ip.dst","tcp.srcport","tcp.dstport","tcp.ack","http.response.code","http.file_data","http.content_type","http.content_length","frame.len","frame.time_relative"]]
    df_response = df_response.rename(columns={
        "ip.src":"ip.dst",
        "ip.dst":"ip.src",
        "tcp.srcport":"tcp.dstport",
        "tcp.dstport":"tcp.srcport",
        "tcp.ack":"tcp.nxtseq",
        "http.file_data":"http.response_body",
        "frame.time_relative":"response_time",
        "frame.len":"frame.response_len"
    })

    df_result = pd.merge(df_request,df_response,on=["ip.dst","ip.src","tcp.dstport","tcp.srcport","tcp.nxtseq"],how='left')
    df_result = df_result.drop(axis=1,columns=['tcp.nxtseq'])
    
    
    df_result.to_csv(output_file,index=False)
    
    print("Completed Conversation merge！")
    print("Extract {} http info to{}!".format(input_file,output_file))

def floder_pcap_analysis_http(path,n_jobs=5):
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

    Parallel(n_jobs=n_jobs)(delayed(http_pcap2csv)(file) for file in file_l)


#floder_pcap_analysis_http("//Volumes/PassPort/DataCon/datacon2021/网络流量分析/datacon2021_traffic_cs2_http/http_sample/")
http_pcap2csv("/Volumes/PassPort/DataCon/datacon2021/网络流量分析/datacon2021_traffic_cs2_http/http_stage2.pcap")

# df = pd.read_csv("./data/output/心跳包.csv")

# print(df.head())

# print(df.columns)