import sys
sys.path.append('../')

import os
import re
import json
import pandas as pd
from collections import defaultdict
from tqdm import tqdm
import numpy as np
from logparser import Drain
import random

import sys
sys.path.append("../")
sys.path.append("../../")

import os
dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, '../deeplog')


import argparse
import torch

from bert_pytorch.dataset import WordVocab
# from bert_pytorch import Predictor, Trainer
from bert_pytorch import ReqPredictor
from bert_pytorch.dataset.utils import seed_everything

options = dict()
options['device'] = 'cuda' if torch.cuda.is_available() else 'mps' if torch.backends.mps.is_available() else 'cpu'
options["output_dir"] = "../output/http/"
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

print("\n\nLade ML Modelle …", end='')
options["model"] = torch.load(options["model_path"], map_location=torch.device('cpu'))
options["center_dict"] = torch.load(options["model_dir"] + "best_center.pt", map_location=torch.device('cpu'))
print(" - Erledigt!")

# seed_everything(seed=4711)

# get [log key, delta time] as input for deeplog
# input_dir  = os.path.expanduser('~/.dataset/http/')
input_dir  = '../../data/'
output_dir = '../output/http/'  # The output directory of parsing results
log_file   = "mein_elba_requests_temp.txt"  # The input log file name

log_file_orig   = "mein_elba_requests_full.log"  # The input log file name
log_structured_file = output_dir + log_file + "_structured.csv"
log_templates_file1 = output_dir + log_file_orig + "_templates.csv"
log_templates_file2 = output_dir + log_file + "_templates.csv"
log_sequence_file = output_dir + log_file + "http_sequence.csv"

def mapping():
    log_temp = pd.read_csv(log_templates_file1)
    log_temp.sort_values(by = ["Occurrences"], ascending=False, inplace=True)
    log_temp_dict1 = {event: idx+1 for idx , event in enumerate(list(log_temp["EventId"])) }
    print(log_temp_dict1)

    log_temp = pd.read_csv(log_templates_file2)
    log_temp.sort_values(by = ["Occurrences"], ascending=False, inplace=True)
    log_temp_dict2 = {event: idx+1 for idx , event in enumerate(list(log_temp["EventId"])) }
    print(log_temp_dict2)

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
    print("Loading", log_file)
    df = pd.read_csv(log_file, engine='c',
            na_filter=False, memory_map=True, dtype={'Date':object, "Time": object})

    with open(output_dir + 'mein_elba_requests_temp.txt' + "http_log_templates.json", "r") as f:
        event_num = json.load(f)
    df["EventId"] = df["EventId"].apply(lambda x: event_num.get(x, -1))

    data_dict = defaultdict(list) #preserve insertion order of items
    for idx, row in tqdm(df.iterrows()):
        blkId_list = re.findall(r'(blk_-?\d+)', row['Content'])
        blkId_set = set(blkId_list)
        for blk_Id in blkId_set:
            data_dict[blk_Id].append(row["EventId"])

    data_df = pd.DataFrame(list(data_dict.items()), columns=['BlockId', 'EventSequence'])
    data_df.to_csv(log_sequence_file, index=None)
    print("http sampling done")


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
    print("normal size {0}, training size {1}".format(normal_len, train_len))

    train = normal_seq.iloc[:train_len]
    # test_normal = normal_seq.iloc[train_len:]
    # test_abnormal = abnormal_seq

    df_to_file(train, output_dir + "train_reqseq")
    # df_to_file(test_normal, output_dir + "test_normal")
    # df_to_file(test_abnormal, output_dir + "test_abnormal")
    print("generate train test data done")


def list_to_file(lines, file_name):
    with open(file_name, 'w') as f:
        for line in lines:
            f.write(f'{line}\n')

def df_to_file(df, file_name):
    with open(file_name, 'w') as f:
        for _, row in df.items():
            f.write(' '.join([str(ele) for ele in eval(row)]))
            f.write('\n')


if __name__ == "__main__":
    # 1. parse http log
    # log_format = '<Date> <Time> <Pid> <Level> <Component>: <Content>'  # http log format
    log_format = '<Date> <Time> <State> <Reason> <ContentType> <Accept> <Host> <Method> <Content>'  # http log format

    # log_reqseq = [] # log sequence of 10 requests (strings from requests_full_log)

    labels = []
    preds = []
    acc = 100.0

    # read lines from log file
    with open(input_dir + log_file_orig) as f:
        log_full = f.readlines()

    # parse all r"(?<=blk_)[-\d]+" from log_full
    blk_id_list = [re.findall(r"(blk_[-\d]+)", x)[0] for x in log_full]
    # choose random element from blk_id_list
    # blk_id_ = random.choice(blk_id_list)

    for blk_id_ in tqdm(blk_id_list, desc=f'Acc {acc}'):
        # filter by string
        log_reqseq = [x for x in log_full if blk_id_ in x]
        assert len(log_reqseq) == 10

        anomalies = pd.read_csv(input_dir + 'anomaly_label.csv')
        # get label of anomalies with blk_id_
        label = anomalies[anomalies['BlockId']==blk_id_]['Label']
        label = label.values[0]
        isNormal = label == 'Anomaly'
        labels.append(isNormal)

        parser(log_reqseq, log_format, 'drain')
        mapping() # generates http_log_templates.json
        http_sampling(log_structured_file) # input: log_structured_file, generates http_sequence.csv
        generate_train_test(log_sequence_file) #, n=4855)

        # for line in log_reqseq:
        #     print(line.strip())
        # print()
        print(f"Ground truth label: {label} from BlockId {blk_id_}\n---\n")

        pred = ReqPredictor(options).predict()
        preds.append(pred[0])

        # calculate accuracy from labels and preds
        labels_ = np.array(labels)
        preds_ = np.array(preds)

        acc = np.sum(labels_ == preds_) / len(labels_)
        print(f"Accuracy: {acc}")
        print('\n---\n')

    # calculate accuracy from labels and preds
    labels_ = np.array(labels)
    preds_ = np.array(preds)

    acc = np.sum(labels_ == preds_) / len(labels_)
    print(f"Accuracy: {acc}")