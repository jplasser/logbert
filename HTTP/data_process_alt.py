import sys
sys.path.append('../')

import os
import gc
import pandas as pd
import numpy as np
from logparser import Spell, Drain
import argparse
from tqdm import tqdm
from logdeep.dataset.session import sliding_window

tqdm.pandas()
pd.options.mode.chained_assignment = None

PAD = 0
UNK = 1
START = 2

# data_dir = os.path.expanduser("~/.dataset/http")
data_dir  = '../../data/'
output_dir = "../output/http/"
log_file   = "mein_elba_requests_dump_train.txt"  # The input log file name


# In the first column of the log, "-" indicates non-alert messages while others are alert messages.
def count_anomaly():
    total_size = 0
    normal_size = 0
    with open(data_dir + log_file, encoding="utf8") as f:
        for line in f:
            total_size += 1
            if line.split(' ',1)[0] == '-':
                normal_size += 1
    print("total size {}, abnormal size {}".format(total_size, total_size - normal_size))


# def deeplog_df_transfer(df, features, target, time_index, window_size):
#     """
#     :param window_size: offset datetime https://pandas.pydata.org/pandas-docs/stable/user_guide/timeseries.html#dateoffset-objects
#     :return:
#     """
#     agg_dict = {target:'max'}
#     for f in features:
#         agg_dict[f] = _custom_resampler
#
#     features.append(target)
#     features.append(time_index)
#     df = df[features]
#     deeplog_df = df.set_index(time_index).resample(window_size).agg(agg_dict).reset_index()
#     return deeplog_df
#
#
# def _custom_resampler(array_like):
#     return list(array_like)


def deeplog_file_generator(filename, df, features):
    with open(filename, 'w') as f:
        for _, row in df.iterrows():
            for val in zip(*row[features]):
                f.write(','.join([str(v) for v in val]) + ' ')
            f.write('\n')


def parse_log(input_dir, output_dir, log_file, parser_type):
    # log_format = '<Label> <Id> <Date> <Code1> <Time> <Code2> <Component1> <Component2> <Level> <Content>'#
    log_format = '<Date> <Time> <Reason> <ContentType> <Accept> <Host> <Method> <Content>'  # http log format
    regex = [
            r'(?<=info.raiffeisen.at)(.*)$', # tracking
            # r"(?<=blk_)[-\d]+", # block_id
            r'ELOOE\d{2}[A-Z]\d[A-Z]\d{6}', # Verfügernummer
            r'\d+\.\d+\.\d+\.\d+',  # IP
            r"(/[-\w]+)+",  # file path
            r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$',  # Numbers
            r'(?<=\=)(?:[\s\S]*?(?= \w+=|$))', # text after =
            r'[" \s\.\-](?:0[xX])?[0-9a-fA-F]{8,}["]*', # hex number
            r'\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9]{4}){4}(?!(?:[ ]?[0-9]){3})(?:[ ]?[0-9]{1,2})?\b', # IBAN
        ]
    keep_para = False
    if parser_type == "drain":
        # the hyper parameter is set according to http://jmzhu.logpai.com/pub/pjhe_icws2017.pdf
        st = 0.5  # 0.3  # Similarity threshold
        depth = 5 # 3  # Depth of all leaf nodes
        parser = Drain.LogParser(log_format, indir=input_dir, outdir=output_dir, depth=depth, st=st, rex=regex, keep_para=keep_para)
        parser.parse(log_file)
    elif parser_type == "spell":
        tau = 0.55
        parser = Spell.LogParser(indir=data_dir, outdir=output_dir, log_format=log_format, tau=tau, rex=regex, keep_para=keep_para)
        parser.parse(log_file)

#
# def merge_list(time, activity):
#     time_activity = []
#     for i in range(len(activity)):
#         temp = []
#         assert len(time[i]) == len(activity[i])
#         for j in range(len(activity[i])):
#             temp.append(tuple([time[i][j], activity[i][j]]))
#         time_activity.append(np.array(temp))
#     return time_activity


if __name__ == "__main__":
    #
    #
    # parser = argparse.ArgumentParser()
    # parser.add_argument('-p', default=None, type=str, help="parser type")
    # parser.add_argument('-w', default='T', type=str, help='window size(mins)')
    # parser.add_argument('-s', default='1', type=str, help='step size(mins)')
    # parser.add_argument('-r', default=0.4, type=float, help="train ratio")
    # args = parser.parse_args()
    # print(args)
    #

    ##########
    # Parser #
    #########

    parse_log(data_dir, output_dir, log_file, 'drain')

    #########
    # Count #
    #########
    # count_anomaly()

    ##################
    # Transformation #
    ##################
    # mins
    window_size = 5
    step_size = 1
    train_ratio = 0.4

    df = pd.read_csv(f'{output_dir}{log_file}_structured.csv')

    # data preprocess
    df['datetime'] = pd.to_datetime(df['Date'].astype(str) + 'T' + df['Time'].astype(str), format='%Y%m%dT%H%M%S.%f')
    df["Label"] = 0 # df["Label"].apply(lambda x: int(x != "-"))
    df['timestamp'] = df["datetime"].values.astype(np.int64) // 10 ** 6
    df['deltaT'] = df['datetime'].diff() / np.timedelta64(1, 's')
    df['deltaT'].fillna(0)
    # convert time to UTC timestamp
    # df['deltaT'] = df['datetime'].apply(lambda t: (t - pd.Timestamp("1970-01-01")) // pd.Timedelta('1s'))

    # sampling with fixed window
    # features = ["EventId", "deltaT"]
    # target = "Label"
    # deeplog_df = deeplog_df_transfer(df, features, target, "datetime", window_size=args.w)
    # deeplog_df.dropna(subset=[target], inplace=True)

    # sampling with sliding window
    deeplog_df = sliding_window(df[["timestamp", "Label", "EventId", "deltaT"]],
                                para={"window_size": int(window_size), "step_size": int(step_size)}
                                )

    #########
    # Train #
    #########
    df_normal =deeplog_df[deeplog_df["Label"] == 0]
    df_normal = df_normal.sample(frac=1, random_state=12).reset_index(drop=True) #shuffle
    normal_len = len(df_normal)
    train_len = int(normal_len * train_ratio)

    train = df_normal[:train_len]
    # deeplog_file_generator(os.path.join(output_dir,'train'), train, ["EventId", "deltaT"])
    deeplog_file_generator(os.path.join(output_dir,'train'), train, ["EventId"])

    print("training size {}".format(train_len))


    ###############
    # Test Normal #
    ###############
    test_normal = df_normal[train_len:]
    deeplog_file_generator(os.path.join(output_dir, 'test_normal'), test_normal, ["EventId"])
    print("test normal size {}".format(normal_len - train_len))

    del df_normal
    del train
    del test_normal
    gc.collect()

    #################
    # Test Abnormal #
    #################
    df_abnormal = deeplog_df[deeplog_df["Label"] == 1]
    #df_abnormal["EventId"] = df_abnormal["EventId"].progress_apply(lambda e: event_index_map[e] if event_index_map.get(e) else UNK)
    deeplog_file_generator(os.path.join(output_dir,'test_abnormal'), df_abnormal, ["EventId"])
    print('test abnormal size {}'.format(len(df_abnormal)))
