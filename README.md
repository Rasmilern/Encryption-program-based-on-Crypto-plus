# Design-of-encryption-program-based-on-Crypto-plus

## 1. 程序简介

    （1）文件加密（DES）
    （2）文件完整性检测（MD-5）
    （3）数字签名（RSA）
    （4）数字信封：(DES、RSA和MD-5综合使用)
    （5）图形化实现（VBS）

## 2. 程序设计

### 2.1 总体设计:

    利用Crypto++库中的函数对数据加密；
    通过选择语句实现不同加密选项的执行；通过数组和字符串储存文件中的数据。

### 2.2 功能设计:

    (1) des加密：由于密钥获取需考虑校验位，随机数生成不易。我们使用生成工具产生密钥。程序根据路径产生一个新的txt文件。
    (2) MD5算法：CryptoPP中的FileSource函数可直接对文件操作，生成的hash值存储在txt文件中。比较时对已保存的文件操作。
    (3) 数字签名：利用已实现的MD5算法，将计算好的hash值使用rsa加密后加到文件头部。
    (4) 数字信封：先对文件签名，再使用des加密，再将密钥用rsa算法加密（公钥私钥均储存在文件内，模拟发送和接收方）。接受方先用私钥解密，再用获得的公钥解密文件。 
    (5) 图形化模式：通过VBS输入框获得用户选择与文件名，使用调用cmd运行后台程序，达到加密效果。

## 3. 使用说明

    （1）图形化模式的实现已录屏，见附件MP4文件；   
    （2）命令行模式只需将main函数需要传入的参数换成cin实现，命令行操作截图显示如下。

![5muFHYXwbZ3siaI](https://i.loli.net/2019/09/21/5muFHYXwbZ3siaI.png)
