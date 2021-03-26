# -*- coding: UTF-8 -*-
from keras.models import Sequential,Model
from keras.layers import Dense, Dropout,Input,concatenate
from keras.utils import plot_model
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.cross_validation import train_test_split
from sklearn import metrics
from sklearn import preprocessing
import os
import re
import pickle
import zlib
import math
import numpy as np

""" 
2018-8-9 

先在当前文件夹下创建models文件夹 

"""

webshell_dir="./webshell/webshell/PHP/"
whitefile_dir="./webshell/normal/php/"
white_count=0
black_count=0
max_features=25000
max_document_length=100

def load_files(path):
    files_list=[]
    for r, d, files in os.walk(path):
        for file in files:
            if file.endswith('.php'):
                file_path=path+file
                #print "Load %s" % file_path
                t=load_file(file_path)
                files_list.append(t)
    return  files_list

def load_file(file_path):
    t=""
    with open(file_path) as f:
        for line in f:
            line=line.strip('\n')
            t+=line
    return t
    
def load_file_utf8(file_path):
    t=""
    with open(file_path,'r',encoding='UTF-8') as f:
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
                #print "Load %s" % fulepath
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
    if(x3!=0):
        print "exp-feature！=",x3
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

def get_feature_by_bag_tfidf():
    global white_count
    global black_count
    global max_features
    print "max_features=%d" % max_features
    x=[]
    y=[]
    addition_feature_list = []
    
    webshell_files_list = load_files_re(webshell_dir)
    y1=[1]*len(webshell_files_list)
    black_count=len(webshell_files_list)

    wp_files_list =load_files_re(whitefile_dir)
    y2=[0]*len(wp_files_list)

    white_count=len(wp_files_list)

    print 'webshell_files_list len = ',len(webshell_files_list),'wp_files_list len = ',len(wp_files_list)
    x =webshell_files_list+wp_files_list
    
    #加载人工特征
    for i in range(len(x)):
        data = x[i]
        #print "x[i]:",data
        add_feature = get_addition_feature(data)
        addition_feature_list.append(add_feature)
    
    y=y1+y2
    print 'x len = ',len(x),'y len = ',len(y)
    CV = CountVectorizer(ngram_range=(1, 2), decode_error="ignore",max_features=max_features,
                                       token_pattern = r'\b\w+\b',min_df=1, max_df=1.0)
    
    x=CV.fit_transform(x).toarray()
    xnames=CV.get_feature_names()
#    print 'x CV.toarray = ',x
    transformer = TfidfTransformer(smooth_idf=False)
    x_tfidf = transformer.fit_transform(x)
    x = x_tfidf.toarray()
    
    #将人工特征附在每个向量后面
    """for j in range(len(x)):
        x[j].extend(addition_feature_list[j])"""
    x = np.concatenate((x,addition_feature_list),axis=1)            
#    print 'x tfidf.toarray = ',x
#    print 'y:',y
#    print 'names:',xnames
    print 'names size :',len(xnames)
    
    #save vocabulary
    feature_path = 'models/CVfeature_feature.pkl'
    with open(feature_path, 'wb') as fw:
        pickle.dump(CV.vocabulary_, fw)
        
    tfidftransformer_path = 'models/tfidftransformer_feature.pkl'
    with open(tfidftransformer_path, 'wb') as fw:
        pickle.dump(transformer, fw)
        
    return x,y  

     
def do_metrics(y_test,y_pred):
    print "metrics.accuracy_score:"
    print metrics.accuracy_score(y_test, y_pred)
    print "metrics.confusion_matrix:"
    print metrics.confusion_matrix(y_test, y_pred)
    print "metrics.precision_score:"
    print metrics.precision_score(y_test, y_pred)
    print "metrics.recall_score:"
    print metrics.recall_score(y_test, y_pred)
    print "metrics.f1_score:"
    print metrics.f1_score(y_test,y_pred)

x,y=get_feature_by_bag_tfidf()
print "load %d white %d black" % (white_count,black_count)
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=0)
x_train_main = []
x_train_addition = []
x_test_main = []
x_test_addition = []
for k in range(len(x_train)):
    x_train_main.append(x_train[k][0:max_features])
    x_train_addition.append(x_train[k][-6:])
for m in range(len(x_test)):
    x_test_main.append(x_test[m][0:max_features])
    x_test_addition.append(x_test[m][-6:])
'''
print "len(x_train_addition):",len(x_train_addition)
print "len(x_train_main):",len(x_train_main)
print "len(x_train_addition[0]):",len(x_train_addition[0])
print "len(x_train_main)[0]:",len(x_train_main[0])
'''
main_input = Input(shape=(max_features,), name='main_input')

x = Dense(20, input_dim=max_features, activation='relu')(main_input)
x = Dropout(0.5)(x)
x = Dense(10, activation='relu')(x)
x = Dropout(0.5)(x)
main_out = Dense(10, activation='relu',name='main_out')(x)

auxiliary_input = Input(shape=(6,), name='aux_input')
x = concatenate([main_out, auxiliary_input])

out = Dense(1, activation='sigmoid')(x)
model = Model(inputs=[main_input, auxiliary_input], outputs=[out])
model.compile(loss='binary_crossentropy',
              optimizer='rmsprop',
              metrics=['accuracy'])
model.fit([x_train_main,x_train_addition], [y_train],
          epochs=20,
          batch_size=32)

print "model.trainable_weights:",model.trainable_weights          
print "model.get_weights:",model.get_weights()
weights = np.array(model.get_weights())

print "main_out shape:",main_out.shape
print "main_out data:",main_out[0]

y_predict_list=model.predict([x_test_main,x_test_addition])
y_predict=[]
for i in y_predict_list:
    if i[0] > 0.5:
        y_predict.append(1)
    else:
        y_predict.append(0)

do_metrics(y_test, y_predict)

score = model.evaluate([x_test_main,x_test_addition], y_test, batch_size=32)
#print paragrams
print model.summary()
print "%s: %.2f%%" % (model.metrics_names[1], score[1]*100)
model.save("mlp_feature_model.h5")
#model = load_model('model.h5')
#draw model
#plot_model(model,to_file='mlp.png')
