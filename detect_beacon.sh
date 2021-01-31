#! /usr/bin/env python3

from dateutil import parser
from datetime import datetime
from io import StringIO
from multiprocessing import Pool
import numpy as np
import csv,argparse,time,os,sys,pandas

# lambdas for date stuff
dat = lambda: time.strftime("%Y-%m-%d %H:%M:%S")
date2epoch = lambda x: int(time.mktime(parser.parse(x).timetuple()))
getUtc = lambda x: datetime.utcfromtimestamp(x)

# fields of interest for each protocol -- will be dataframe column names later
protocolFields = {
        "tcp" : ['frame','protocol','source_ip','source_port','dest_ip',\
        'dest_port','frame_length','tcp_flag','data', 'stream', 'date','time']
        }

# command to use in tshark to process pcap files
tsharkCmds = {
        "tcp" : 'tshark -tud -n -r %s -E separator=/t -T fields -e frame.number -e ip.proto -e frame.time -e \
        ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e frame.len -e tcp.flags -e data -e tcp.stream tcp and not "(ipv6 or icmp)" > %s'
        }


# process a pcap file with tshark
# This is saved to a temp file that will be used to create the csv later
def ExtractPcapData(pcap,protocol):
    print( dat(),"Processing:",pcap)

    outputFileName = "%s_%s.txt" % (pcap.split(".")[0],protocol.upper())
    tsharkBaseCmd = tsharkCmds.get(protocol)
    execTsharkCmd = tsharkBaseCmd % (pcap,outputFileName)

    b = os.popen(execTsharkCmd).read()

    return outputFileName


# transform a tshark output file to a csv that can be used with pandas
def CreateCsv(outputFileName,protocol):
    csvEntry = {}

    data = open(outputFileName,"r").read().strip().split("\n")
    csvFileName = outputFileName.replace(".txt",".csv")
    csvFields = protocolFields.get(protocol)

    print( dat(),"Creating:",csvFileName)

    with open(csvFileName,"w") as csvfile:
        writer = csv.DictWriter(csvfile,fieldnames=csvFields) #modeline for automation
        writer.writeheader()

        for entry in data:
            entry = entry.split('\t')

            try:
                timestamp = parser.parse(entry[2].split('.')[0]).strftime("%Y-%m-%d %H:%M:%S")
            except:
                print("There is a problem processing PCAP. If the error occured while processing UDP packets, try upgrading tshark.")
                sys.exit()

            eventDate,eventTime = timestamp.split()
            del entry[2]
            entry.append(eventDate)
            entry.append(eventTime)

            if (protocol == "udp") and (len(csvFields) != len(entry)):
                #No data found in packet
                entry.insert(8,'')
            else:
                pass

            if protocol == "icmp":
                try:
                    identBE,identLE = entry[-6].split(',')
                except:
                    identBE,identLE = ("NA","NA")

                del entry[-6] #ICMP
                entry.append(identBE) #ICMP
                entry.append(identLE) #ICMP

                if len(csvFields) != len(entry):
                    #No data found in packet. This will probably never happen, but just in case.
                    entry.insert(8,'')
                else:
                    pass

            csvEntry = dict(zip(csvFields,entry)) #mode line for automation
            writer.writerow(csvEntry)

    return csvFileName


# crate pandasDataFrame from a pcap csv
def CreateDataFrame(csvFileName,protocol):

        frameName = csvFileName.replace(".csv",".PANDAS")
        pDataframe = pandas.read_csv(csvFileName).fillna('N/A') #create pandas dataframe
        pDataframe.to_pickle("capture1.pkl")
        return pDataframe


def findRegularConnections(pcap_file):
    # if a pickle exists, (This pcap was already processed once), then read the pickle instead of processing again
    if os.path.exists('capture1.pkl'):
        df = pandas.read_pickle('capture1.pkl')
    else:
        # go from pcap to dataframe
        outputFileName = ExtractPcapData(pcap_file,"tcp")
        csvFileName = CreateCsv(outputFileName,"tcp")
        df = CreateDataFrame(csvFileName,"tcp")

    # get the time in a standard format for calculations (cant process if time is a string) 
    df['time'] = pandas.to_datetime(df['time'])

    # group results by source / dest IP
    # this makes it easier to calc the time between connections to the same host
    groups = df.groupby(['source_ip', 'dest_ip'])

    # for each source/dest IP group, print the differences between each connection
    for name, group in groups:
        print(name)
        diff = group['time'].diff()
        diff = diff / np.timedelta64(1, 's') # gets differences in seconds
        diff = diff[diff >= 60] # gets differences in seconds when seconds is >= 60 -- this filters out packets that are part of the same connection (have very very small time differences)
        print(diff) # this is a list of all connections >= 60 between each


def main():
    # parse cmdline args
    aParser = argparse.ArgumentParser()
    aParser.add_argument("--pcap",help="input file")
    aParser.add_argument("--dir",help="directory of pcaps to process")
    args = aParser.parse_args()
    pcap = args.pcap
    directory = args.dir

    if pcap:
        findRegularConnections(pcap)

if __name__=='__main__':
    main()

#END
