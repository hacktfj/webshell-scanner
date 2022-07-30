# Webshell-Scanner
Webshell scanner using deep learning method；  

Method：
1. 对webshell 统计6个特征(压缩比、最长单词、危险函数、恶意特征、信息熵、恶意表达式)；
2. 将webshell 转化为n-gram向量，输入全连接网络 mlp_net（每层节点数依次为：20,10,10,1）
3. 在 mlp_net 的倒数第二层，拼接步骤1的6个特征，然后这16维特征连接到输出层

模型训练代码：mlp_feature.py  
训练好的模型参数：mlp_feature_model.h5  
词袋模型: models文件夹  
扫描器：scan_shell.py  
数据集：webshells.zip  

基于深度学习的webshell扫描器，测试集准确率高于99%  
这项工作基于以下代码，鲁棒性和准确率得到了提升，具有一定抵御对抗扰动（bad words）的效果： https://github.com/duoergun0729/2book/blob/master/code/webshell.py
