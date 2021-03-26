# -*- coding: UTF-8 -*-
from keras.models import Sequential,Model
from keras.layers import Dense, Dropout
from keras.utils import plot_model
from keras.models import load_model
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.cross_validation import train_test_split
from sklearn import metrics
import os
import re
import pickle
import io
import zlib
import math
import numpy as np

""" 
2018-8-9

mlp_feature.py运行完后，当前目录下生成模型文件：mlp_feature_model.h5 ,models文件夹里会创建2个文件

用此代码，可以对单个文件或者网站根目录进行扫描

"""

max_features=25000
max_document_length=100

def load_files(path):
    files_list=[]
    for r, d, files in os.walk(path):
        for file in files:
            if file.endswith('.php'):
                file_path=path+file
                print ("Load %s" % file_path)
                t=load_file(file_path)
                files_list.append(t)
    return  files_list

def load_file_to_list(file_path):
    t=""
    tlist=[]
    with io.open(file_path,'r',encoding='UTF-8') as f:
        for line in f:
            line=line.strip('\n')
            t+=line
    tlist.append(t)
    return tlist

def load_file(file_path):
    t=""
    with open(file_path,'r') as f:
        for line in f:
            line=line.strip('\n')
            t+=line
    return t
    
def load_files_re(dir):
    files_list = []
    g = os.walk(dir)
    for path, d, filelist in g:
        #print d;
        for filename in filelist:
            #print os.path.join(path, filename)
            if filename.endswith('.php') or filename.endswith('.txt'):
                fulepath = os.path.join(path, filename)
                print ("Load %s" % fulepath)
                t = load_file(fulepath)
                files_list.append(t)

    return files_list
#计算压缩比
def get_compression(data):
    results = []
    if not data:
        return "", 0
    compressed = zlib.compress(data)
    ratio = float(len(compressed)) / float(len(data))
    #results.append({"filename":filename, "value":ratio})
    return ratio
    
#统计最长单词
def get_longestwords(data):
    results = []
    if not data:
        return "", 0
    longest = 0
    longest_word = ""
    words = re.split("[\s,\n,\r]", data)
    if words:
        for word in words:
            length = len(word)
            if length > longest:
                longest = length
                longest_word = word
    #results.append({"filename":filename, "value":longest})
    #最长单词/10000，进行压缩
    longest_ratio = float(longest)/float(10000)
    return longest_ratio
    
#统计危险函数
def get_danger_function(data):
    results = []
    if not data:
        return "", 0
    
    valid_regex = re.compile('(eval\(|file_put_contents|base64_decode|python_eval|exec\(|passthru|popen|proc_open|pcntl|assert\(|system\(|shell)', re.I)
    matches = re.findall(valid_regex, data)
    #results.append({"filename":filename, "value":len(matches)})
    #除以100进行压缩
    danger_feature_raio = float(len(matches))/float(100)
    return danger_feature_raio

#统计恶意特征
def get_exp_feature(data):
    results = []
    if not data:
        return "", 0
    valid_regex = re.compile('(@\$_\[\]=|\$_=@\$_GET|\$_\[\+""\]=)', re.I)
    matches = re.findall(valid_regex, data)
    #results.append({"filename":filename, "value":len(matches)})
    #除以10进行压缩
    exp_feature_raio = float(len(matches))/float(10)
    return len(matches)
    
#计算信息熵
def get_entropy(data):
    results = []
    if not data:
        return 0
    entropy = 0
    stripped_data =data.replace(' ', '')
    for x in range(256):
        p_x = float(stripped_data.count(chr(x)))/len(stripped_data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    #results.append({"filename":filename, "value":entropy})
    #除以10进行压缩
    entropy_raio = float(entropy)/float(10)
    return entropy
    
#查找恶意表达式
def get_eval(data):
    results = []
    if not data:
        return "", 0
        # Lots taken from the wonderful post at http://stackoverflow.com/questions/3115559/exploitable-php-functions
    valid_regex = re.compile('(eval\(\$(\w|\d))', re.I)
    matches = re.findall(valid_regex, data)
    
    #results.append("value":len(matches))
    #除以5进行压缩
    matches_raio = float(len(matches))/float(5)
    return matches_raio
    
#计算重合指数 

#加载人工特征
def get_addition_feature(data):
    addition_feature = []
    x1 = get_eval(data)
    x2 = get_entropy(data)
    x3 = get_exp_feature(data)
    x4 = get_danger_function(data)
    x5 = get_longestwords(data)
    x6 = get_compression(data)
    addition_feature = [x1,x2,x3,x4,x5,x6]
    #归一化
    """min_max_scaler = preprocessing.MinMaxScaler()
    addition_feature_minmax = min_max_scaler.fit_transform([addition_feature])"""
    #print "addition_feature_minmax:",addition_feature_minmax
    print "addition_feature_",addition_feature
    #return addition_feature_minmax[0]
    return addition_feature
    
def check_webshell(model,file_path):
    t = load_file_to_list(file_path)
    print t
    t_feature = load_file(file_path)
    # 加载特征
    feature_path = 'models/CVfeature_feature.pkl'
    loaded_CV = CountVectorizer(decode_error="replace", vocabulary=pickle.load(open(feature_path, "rb")))
    # 加载TfidfTransformer
    tfidftransformer_path = 'models/tfidftransformer_feature.pkl'
    tfidftransformer = pickle.load(open(tfidftransformer_path, "rb"))
    #测试用transform，表示测试数据，为list
    x_tfidf = tfidftransformer.transform(loaded_CV.transform(t))
    x = x_tfidf.toarray()
    #计算人工特征
    add_feature = [get_addition_feature(t_feature)]
    add_feature = np.array(add_feature)
    print "x.shape",x
    print "add_feature.shape",add_feature
    y_pre = model.predict([x,add_feature])
    print "[+]  Scan 1 file y_predict = %f ,file_path = %s" % (y_pre,file_path)

def scan_webshell(model,dir):
    all=0
    all_php=0
    webshell=0
    #models_feature_attackdata_bak/CVfeature_feature.pkl   对应下面model
    feature_path = 'models_feature_attackdata_bak/CVfeature_feature.pkl'
    loaded_CV = CountVectorizer(decode_error="replace", vocabulary=pickle.load(open(feature_path, "rb")))
    # 加载TfidfTransformer
    tfidftransformer_path = 'models_feature_attackdata_bak/tfidftransformer_feature.pkl'
    tfidftransformer = pickle.load(open(tfidftransformer_path, "rb"))
    
    g = os.walk(dir)
    for path, d, filelist in g:
        for filename in filelist:
            fulepath=os.path.join(path, filename)
            t = load_file(fulepath)
            #计算人工特征
            add_feature = get_addition_feature(t)

            x_tfidf = tfidftransformer.transform(loaded_CV.transform(t))
            x2 = x_tfidf.toarray()
            
            y_pred = model.predict([x2,add_feature])
            all+=1
            if filename.endswith('.php'):
                all_php+=1
            if y_pred[0] > 0.5:
                print "%s is webshell" % fulepath
                webshell+=1

    print "Scan %d files(%d php files),%d files is webshell" %(all,all_php,webshell)

#mlp_feature_model_datattack_bak.h5 ，是用不包含原始webshell，仅叠加噪声webshell数据集训练的。
model = load_model('mlp_feature_model.h5')
check_webshell(model,"./shell/test1.php")
#check_webshell(model,"./shell/test1toattack.php")
#check_webshell(model,"./shell/comment.php")
#scan_webshell(model,whitefile_dir)
