"""
Copyright by Lucifer.

Author by:Lucifer
If you have any question about this file,please send e-mail to :Lucifer<gudawei@iie.ac.cn>
"""
from __future__ import division
import os
import sys
import string
import time
class Flowdata(object):
    """
    This class will hold a flowdata data,to analysis the DDoS attack.
    """

    """
    This is the static variable space
    """
    ljd = 0
    oldtime = datetime.datetime.strptime('00000000000000',"%Y%m%d%H%M%S")
    time_delta = 1
    out_put_file = {}
    liuliang = 0
    cha_liuliang = 0
    
    def __init__(self,line):
        """
        This function can create a Flowdata from a str.
        The str is read from the data file.
        the str contains 22  fields.

        Fields:
        0-rip:the IP recieve from the previous router.
        1-sip:the flow's source ip.
        2-dip:the flow's dip.
        3-nip:the flow's next hoop.
        4-input:
        5-output:
        6-packets:the packets of the flow.
        7-bytes:the bytes of the flow.
        8-time:the time of the flow.
        9-sport:the source port of the flow.
        10-dport：the destination port of the flow.
        11-flags:the flags and with each tcp package header.
        12-proto:the proto of the flow
        13-tos:
        14-sas:
        15-das:
        16-scc:
        17-dcc:
        18-province:province of the site
        19-operator:
        20-spc:
        21-dpc:
        """
        words = line.split('\t')
        self.rip = words[0]
        self.sip = words[1]
        self.dip = words[2]
        self.nip = words[3]
        self.input = words[4]
        self.output = words[5]
        self.packets = string.atoi(words[6])
        self.bytes = string.atoi(words[7])
        self.time = str_to_time(words[8])
        self.sport = words[9]
        self.dport = words[10]
        self.flags = words[11]
        self.proto = words[12]
        self.tos = words[13]
        self.sas = words[14]
        self.das = words[15]
        self.scc = words[16]
        self.dcc = words[17]
        self.province = words[18]
        self.operator = words[19]
        self.spc = words[20]
        self.dpc = words[21]

    def process(self):
        deltatime = self.time - oldtime
        total_seconds = deltatime.total_seconds()
        if total_seconds > time_delta:
            self.write_file()
        else:
            liuliang = liuliang + self.bytes



if __name__ == '__main__':
    """
    This is the test fuction,you can use this model as a python program.
    use this test model as "python ljd.py srcfolder desfolder"
    this model will analysis the data automicly
    """
    src= sys.argv[1]
    des= sys.argv[2]
    if src[-1]<>'/':
        src+='/'
    if des[-1]<>'/':
        des+='/'
    main()

def str_to_time(line):
    """
    This function formate a str to a time.
    
    Parameters:
    line:a str of time ,such as :20151010122123
    
    Returns:
    a time val.
    """
    return datetime.datetime.strptime(line,"%Y%m%d%H%M%S")

def output_dic(dic,oldtime):
    """
    Format a dic to a str,
    the str format as "oldtime  key1    value1  key2    value2 ..."
    
    Parameters:
    dic:a dictionary includ the protocol distribution.
    oldtime:the calculate timestr.

    Return:
    the formated str
    """
    wline="%s" %oldtime
    for keys in dic:
        wline="%s\t%s\t%d" %(wline,keys,dic[keys])
    wline='%s\n' %wline
    return wline

def main(src,des):
    """
    Run the auto analysis model.
    
    Parameters：
    src:source folder of date.
    des:destination folder of the output.The folder will be created if there is
        no des folder.there some sufolder to save the result.

    Yield:
    folders and files of the result will created at the destinationg folder.
    """
    command='mkdir -p '+des+'ljd '+des+'ll '+des+'xy '+des+'port '+des+'other'
    os.system(command)

    files=os.listdir(src)
    for file in files:
        file_t=open(src+file)
        line=file_t.readline()
        flow=Flowdata(line)
        
"""        words=line.split('\t')
        file_des_ll=open(des+'ll/ll'+file,'ab+')
        file_des_xy=open(des+'xy/xy'+file,'ab+')
        lltotal=string.atoi(words[7])
        pktotal=string.atoi(words[6])
        ljd=1
        prell=0
        prepk=0
        preljd=0
        if words[13] in dic_xy:
            dic_xy[words[13]]+=1
        else:
            dic_xy[words[13]]=1
        oldtime=(words[8][0:12])
        
        while 1:
            line=file_t.readline()
            if not line:
                break
            words=line.split('\t')
            if words[8][0:12]==oldtime:
                lltotal+=string.atoi(words[7])
                pktotal+=string.atoi(words[6])
                ljd+=1

                if words[13] in dic_xy:
                    dic_xy[words[13]]+=1
                else:
                    dic_xy[words[13]]=1
            else:
                epk=pktotal-prepk
                ell=lltotal-prell
                eljd=ljd-preljd
                if epk < 0:
                    epk= -epk
                if ell < 0:
                    ell= -ell
                if eljd<0:
                    eljd= -eljd
                epkf=(epk+1)/(pktotal+1)
                ellf=(ell+1)/(lltotal+1)
                eljdf=(eljd+1)/(ljd+1)
                wline="%s\t%d\t%d\t%f\t%d\t%d\t%f\t%d\t%d\t%f\n" %(oldtime,pktotal,epk,epkf,lltotal,ell,ellf,ljd,eljd,eljdf)
                prepk=pktotal
                prell=lltotal
                preljd=ljd
                file_des_ll.write(wline)
    
                wline=output_dic(dic_xy,oldtime)
                file_des_xy.write(wline)
                
                dic_xy={}
                pktotal=string.atoi(words[6])
                lltotal=string.atoi(words[7])
                ljd=1
                oldtime=words[8][0:12]
            
        epk=pktotal-prepk
        ell=lltotal-prell
        eljd=ljd-preljd
        if epk < 0:
            epk= -epk
        if ell < 0:
            ell= -ell
        if eljd<0:
            eljd= -eljd
        epkf=(epk+1)/(pktotal+1)
        ellf=(ell+1)/(lltotal+1)
        eljdf=(eljd+1)/(ljd+1)
        wline="%s\t%d\t%d\t%f\t%d\t%d\t%f\t%d\t%d\t%f\n" %(oldtime,pktotal,epk,epkf,lltotal,ell,ellf,ljd,eljd,eljdf)
        file_des_ll.write(wline)

        wline=output_dic(dic_xy,oldtime)
        file_des_xy.write(wline)
            
        dic_xy={}
        file_des_ll.close()
        file_des_xy.close()
        file_t.close()



"""
def process(Flowdata)
