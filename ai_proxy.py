"""
MITMPROXY - Analysiert Requests/Responses mittels AI und lehnt bei Anomalien ab.
"""
import datetime
import urllib

import os
import re
import json
import pandas as pd
from collections import defaultdict
from tqdm import tqdm
import numpy as np
from logparser import Drain
import random
import time

import sys
sys.path.append("../")
# sys.path.append("../../")

import argparse
import torch

from bert_pytorch.dataset import WordVocab
from bert_pytorch import ReqPredictor
from bert_pytorch.dataset.utils import seed_everything

from mitmproxy import http
# from mitmproxy import HTTPResponse

# Clearing the Screen
os.system('cls')
print("Man-in-the-middle-Proxy RSG/Application Security v2.0.0")

# Host-Whitelist für Requests, welche generell verarbeitet werden
HOST_WHITELIST = ['idp.tst.pi.r-itservices.at', 'pfp.tstux.pi.r-itservices.at',
                  'info.raiffeisen.at', 'www.raiffeisen.at']
# Whitelists für Header-Daten
REQUEST_HEADERS_WHITELIST = ['accept', 'host']
RESPONSE_HEADERS_WHITELIST = ['content-type']

# Sliding Window Größe für Anomalieprüfung
REQUEST_SLIDING_WINDOW_COUNT = 10

# Liste von Requests für Anomalieprüfung
list_of_requests = []

# Options for the LogBERT model
options = dict()
options['device'] = 'cuda' if torch.cuda.is_available() else 'mps' if torch.backends.mps.is_available() else 'cpu'
options["output_dir"] = "./output/http/"
options["model_dir"] = options["output_dir"] + "bert/"
options["model_path"] = options["model_dir"] + "best_bert.pth"
options["train_vocab"] = options["output_dir"] + "train"
options["vocab_path"] = options["output_dir"] + "vocab.pkl"  # pickle file

options["window_size"] = 128
options["adaptive_window"] = True
options["seq_len"] = 512
options["max_len"] = 512 # for position embedding
options["min_len"] = 10
options["mask_ratio"] = 0.65
# sample ratio
options["train_ratio"] = 1
options["valid_ratio"] = 0.1
options["test_ratio"] = 1 # 0.01 # 1

# features
options["is_logkey"] = True
options["is_time"] = False

options["hypersphere_loss"] = True
options["hypersphere_loss_test"] = False

options["scale"] = None # MinMaxScaler()
options["scale_path"] = options["model_dir"] + "scale.pkl"

# model
options["hidden"] = 256 # embedding size
options["layers"] = 4
options["attn_heads"] = 4

options["epochs"] = 200
options["n_epochs_stop"] = 10
options["batch_size"] = 512 if torch.cuda.is_available() else 4 if torch.backends.mps.is_available() else 4 # 128 MPS

options["corpus_lines"] = None
options["on_memory"] = True
options["num_workers"] = 1
options["lr"] = 1e-3
options["adam_beta1"] = 0.9
options["adam_beta2"] = 0.999
options["adam_weight_decay"] = 0.00
options["with_cuda"]= True
options["cuda_devices"] = None
options["log_freq"] = None

# predict
options["num_candidates"] = 6
options["gaussian_mean"] = 0
options["gaussian_std"] = 1
options["seq_th"] = 0.8

input_dir  = '../data/'
output_dir = './output/http/'  # The output directory of parsing results
log_file   = "mein_elba_requests_temp.txt"  # The input log file name

log_file_orig   = "mein_elba_requests_full.log"  # The input log file name
log_structured_file = output_dir + log_file + "_structured.csv"
log_templates_file1 = output_dir + log_file_orig + "_templates.csv"
log_templates_file2 = output_dir + log_file + "_templates.csv"
log_sequence_file = output_dir + log_file + "http_sequence.csv"
log_format = '<Date> <Time> <State> <Reason> <ContentType> <Accept> <Host> <Method> <Content>'  # http log format

print("\n\nLade ML Modelle …", end='')
options["model"] = torch.load(options["model_path"], map_location=torch.device('cpu'))
options["center_dict"] = torch.load(options["model_dir"] + "best_center.pt", map_location=torch.device('cpu'))
print(" - Erledigt!")

### Functions used by LogBERT prediction
def mapping():
    log_temp = pd.read_csv(log_templates_file1)
    log_temp.sort_values(by = ["Occurrences"], ascending=False, inplace=True)
    log_temp_dict1 = {event: idx+1 for idx , event in enumerate(list(log_temp["EventId"])) }
    # print(log_temp_dict1)

    log_temp = pd.read_csv(log_templates_file2)
    log_temp.sort_values(by = ["Occurrences"], ascending=False, inplace=True)
    log_temp_dict2 = {event: idx+1 for idx , event in enumerate(list(log_temp["EventId"])) }
    # print(log_temp_dict2)

    # remove new keys that already exist
    for k in log_temp_dict1.keys():
        log_temp_dict2.pop(k, None)

    log_temp_dict = log_temp_dict1 | log_temp_dict2

    with open (output_dir + log_file + "http_log_templates.json", "w") as f:
        json.dump(log_temp_dict, f)


def parser(log_file, log_format, type='drain'):
    # <Date> <Time> <Pid> <Level> <Component>: <Content>'  # http log format
    regex = [
        r'(?<=info.raiffeisen.at)(.*)$', # tracking
        # r"(?<=blk_)[-\d]+", # block_id
        r'ELOOE\d{2}[A-Z]\d[A-Z]\d{6}', # Verfügernummer
        r'\d+\.\d+\.\d+\.\d+',  # IP
        r"(/[-\w]+)+",  # file path
        r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$',  # Numbers
        r'(?<=\=)(?:[\s\S]*?(?= \w+=|$))', # text after
        r'[" \s\.\-](?:0[xX])?[0-9a-fA-F]{8,}["]*', # hex number
        r'\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9]{4}){4}(?!(?:[ ]?[0-9]){3})(?:[ ]?[0-9]{1,2})?\b', # IBAN
    ]
    # the hyper parameter is set according to http://jmzhu.logpai.com/pub/pjhe_icws2017.pdf
    st = 0.5  # Similarity threshold
    depth = 5  # Depth of all leaf nodes

    # write temp file for parser
    tmpfilename = "mein_elba_requests_temp.txt"
    list_to_file(log_file, input_dir + tmpfilename)

    parser = Drain.LogParser(log_format, indir=input_dir, outdir=output_dir, depth=depth, st=st, rex=regex, keep_para=False)
    parser.parse(tmpfilename)


def http_sampling(log_file, window='session'):
    # we need the following files here: http_log_templates.json
    #

    assert window == 'session', "Only window=session is supported for http dataset."
    # print("Loading", log_file)
    df = pd.read_csv(log_file, engine='c',
            na_filter=False, memory_map=True, dtype={'Date':object, "Time": object})

    with open(output_dir + 'mein_elba_requests_temp.txt' + "http_log_templates.json", "r") as f:
        event_num = json.load(f)
    df["EventId"] = df["EventId"].apply(lambda x: event_num.get(x, -1))

    data_dict = defaultdict(list) #preserve insertion order of items
    # for idx, row in tqdm(df.iterrows()):
    for idx, row in df.iterrows():
        blkId_list = re.findall(r'(blk_-?\d+)', row['Content'])
        blkId_set = set(blkId_list)
        for blk_Id in blkId_set:
            data_dict[blk_Id].append(row["EventId"])

    data_df = pd.DataFrame(list(data_dict.items()), columns=['BlockId', 'EventSequence'])
    data_df.to_csv(log_sequence_file, index=None)
    # print("http sampling done")


def generate_train_test(http_sequence_file, n=None, ratio=0.8):
    # blk_label_dict = {}
    # blk_label_file = os.path.join(input_dir, "anomaly_label.csv")
    # blk_df = pd.read_csv(blk_label_file)
    # for _ , row in tqdm(blk_df.iterrows()):
    #     blk_label_dict[row["BlockId"]] = 1 if row["Label"] == "Anomaly" else 0

    seq = pd.read_csv(http_sequence_file)
    seq["Label"] = 0 #add label to the sequence of each blockid

    normal_seq = seq[seq["Label"] == 0]["EventSequence"]
    normal_seq = normal_seq.sample(frac=1, random_state=20) # shuffle normal data

    # abnormal_seq = seq[seq["Label"] == 1]["EventSequence"]
    normal_len = len(normal_seq)
    train_len = normal_len
    # print("normal size {0}, training size {1}".format(normal_len, train_len))

    train = normal_seq.iloc[:train_len]
    # test_normal = normal_seq.iloc[train_len:]
    # test_abnormal = abnormal_seq

    df_to_file(train, output_dir + "train_reqseq")
    # df_to_file(test_normal, output_dir + "test_normal")
    # df_to_file(test_abnormal, output_dir + "test_abnormal")
    # print("generate train test data done")


def list_to_file(lines, file_name):
    with open(file_name, 'w') as f:
        for line in lines:
            f.write(f'{line}\n')

def df_to_file(df, file_name):
    with open(file_name, 'w') as f:
        for _, row in df.items():
            f.write(' '.join([str(ele) for ele in eval(row)]))
            f.write('\n')

### ### ### ### ###

print("Starte Proxyservice …", end=' - ')

# Filtert Header-Daten aus den übergebenen Daten.
#   param: headers: Header-Daten
#   param: whitelist: Whitelist zum Filtern
#   return: Gefilterte Header-Daten
def __get_header_data_as_string(headers,
                                whitelist):
    header_values_as_list = []  # Header [<Key>: <Value>]
    for whitelist_header_key in whitelist:
        header_found = False
        for header_key, header_value in headers.items():
            if header_key.lower() == whitelist_header_key.lower():
                header_values_as_list.append(header_value)
                header_found = True
                break
        if not header_found:
            header_values_as_list.append('')
    return header_values_as_list


# MITMPROXY-Response-Methode: Intercepted den Response
# Dokumentation der Klasse: https://docs.mitmproxy.org/stable/api/mitmproxy/http.html#HTTPFlow
def response(flow: http.HTTPFlow) -> None:
    global list_of_requests

    # Request-Daten auslesen
    request_host = flow.request.host  # Host [sso.raiffeisen.at]
    if request_host in HOST_WHITELIST:
        current_output_as_list = []
        current_output_as_list.append(str(datetime.datetime.now().strftime('%Y%m%d')))  # Aktuelles Datum
        current_output_as_list.append(str(datetime.datetime.now().strftime('%H%M%S.%f')))  # Aktuelle Uhrzeit
        current_output_as_list.append(str(flow.response.status_code))  # HTTP Status Code
        current_output_as_list.append(str(flow.response.reason))  # Rückmeldung in Textform
        current_output_as_list += __get_header_data_as_string(flow.response.headers, RESPONSE_HEADERS_WHITELIST)  # Response Header
        current_output_as_list += __get_header_data_as_string(flow.request.headers, REQUEST_HEADERS_WHITELIST)  # Request Header

        request_method = str(flow.request.method)  # Methode [GET|POST|PUT|DELETE]
        request_path = str(flow.request.path)  # URL-Pfad [/mein-login/]
        # Pfad aufbereiten => Variablen werden dekodiert und durch Leerzeichen getrennt
        request_path_unquoted = urllib.parse.unquote(request_path, encoding='utf-8', errors='replace')
        list_of_path_variables = request_path_unquoted[request_path_unquoted.find('?') + 1:].split('&')
        request_path_unquoted_final = request_path_unquoted[:request_path_unquoted.find('?') + 1] + ' '.join(list_of_path_variables)
        # Content zusammensetzen aus HTTP-Method, Host und Pfad mit aufbereiteten Variablen
        content = request_method + ' ' + request_host + request_path_unquoted_final
        current_output_as_list.append(content)  # Aufbereiteter Request Content

        if len(list_of_requests) < REQUEST_SLIDING_WINDOW_COUNT:
            # print(len(list_of_requests), end=' ', flush=True)
            print('#', end='', flush=True)
            list_of_requests.append(current_output_as_list)
        else:
            # print(len(list_of_requests))
            print('#')
            list_of_requests = list_of_requests[1:]
            list_of_requests.append(current_output_as_list)

            # Request-String mittels AI prüfen
            safe_requests = check_request_by_ai(list_of_requests)
            # Request ablehnen, wenn dieser eine Anomalie darstellt
            if not safe_requests:
                # pass
                flow.response = http.Response.make(
                    200,  # (optional) status code
                    "Potentiell bösartiger Request erkannt.",  # (optional) content
                    {"Content-Type": "text/html"},  # (optional) headers
                )

            list_of_requests = list_of_requests[-1:]


# Prüft den übergebenen String auf Anomalien mittels AI.
#   param: request_string: Zu prüfender String
#   return Prüfungsergebnis
def check_request_by_ai(request_string):
    print("Anomalieerkennung der aufgezeichneten Sequenz läuft …")
    log_reqseq = [' '.join(req) + ' blk_1234567890123456789' for req in request_string]
    print(log_reqseq[-1][:22], end=' - ')
    assert len(log_reqseq) == 10
    
    parser(log_reqseq, log_format, 'drain')
    mapping() # generates http_log_templates.json
    http_sampling(log_structured_file) # input: log_structured_file, generates http_sequence.csv
    generate_train_test(log_sequence_file)

    # predict label
    pred = ReqPredictor(options).predict()
    print(f"Logsequenz wurde als {'potentielle Anomalie' if pred[0] else '»normal«'} identifiziert.\n---\n")
    if pred[0]:
        print("Ausgabe der Anomaliesequenz:")
        for log in log_reqseq:
            print(log)
        print()

    return not pred[0]
    
print("Proxy läuft und wartet auf Requests.")
print()