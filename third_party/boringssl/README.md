# ut-boringssl

boringssl支持国密算法和通信协议  

# Check：
./bssl s_client -debug -connect sm2only.ovssl.cn    
./bssl s_client -debug -connect sm2test.ovssl.cn    
./bssl s_client -debug -connect ebssec.boc.cn -max-version gmtls    

双向验证 
https://sm2auth.ovssl.cn/   

./bssl s_client -debug -connect gm.trustasia.com -cipher GMTLS_SM2_WITH_SM4_SM3     
./bssl s_client -debug -connect wifi.360.cn -cipher GMTLS_SM2_WITH_SM4_SM3 -max-version gmtls   
./bssl s_client -debug -connect spcjsac.gsxt.gov.cn -cipher GMTLS_SM2_WITH_SM4_SM3 -max-version gmtls   
./bssl s_client -debug -connect www.wotrus.com  
./bssl s_client -debug -connect gm.trustasia.com:8443   
./bssl s_client -debug -connect www.cee.edu.cn  

回收证书页测试 ./bssl s_client -debug -connect sm2ovg4.revoked.sheca.com:4443   
ok页面测试    ./bssl s_client -debug -connect sm2ovg4.good.sheca.com:4443   
过期证书页测试 ./bssl s_client -debug -connect sm2ovg4.expired.sheca.com:4443   

服务有问题  	
./bssl s_client -debug -connect demossl-sm2-valid.bjca.org.cn:8004 -cipher GMTLS_SM2_WITH_SM4_SM3 -max-version gmtls    
./bssl s_client -debug -connect demossl-sm2-expired.bjca.org.cn:8005    
./bssl s_client -debug -connect demossl-sm2-revoked.bjca.org.cn:8006    

非国密测试  
./bssl s_client -debug -connect www.baidu.com   
./bssl s_client -debug -connect www.qq.com  

# Based on
[GmSSL](https://github.com/guanzhi/GmSSL/)  
[TASSL-1.1.1b](https://github.com/jntass/TASSL-1.1.1b)  
[TASSL](https://github.com/jntass/TASSL/)   

# License
```
Copyright 2020 Uniontech, Inc.
```