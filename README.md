# LindgeBreaker/凌极爆破者(目前停更)  
机房爆破工具,针对凌极云桌面.  
"Lindge","凌极"是"上海凌极软件有限公司"的商标,该公司拥有该商标的所有权.

咳咳,在此感谢我的同班同学,是他们坚持不懈地破解机房控制系统(却从没成功),才让我脑中闪过灵感,造出这个机房爆破工具--凌极爆破者.(呵呵,他们绝对看不到  
# 项目简介  
本项目为爆破工具,针对凌极云桌面,利用凌极系统的弱点,定点爆破,从而达到HAPPY的目的. 
# 管理员模块
嗯...从v1.2,加了个管理员模块,可以直接爆破局域网内其他LB程序(反方向的钟无法恢复程序),相当于`团灭`.好吧,别让每个人都是管理员,这样谁还用啊...
# 实现原理  
控制机借助机房服务器,向受控机发出控制命令,而受控机上的凌极系统进程接受命令,进入受控模式.本工具在受控机被控制之前,定点爆破相关进程,使受控机HAPPY. 
我还加了个授权机制,一个授权码,一个授权文件,这样,你就可以限定某些人可以使用(可以改代码,先看开源协议).
# 食用方法  
> ### Py文件  
> 主程序**以管理员身份**运行,其他文件必须在同级目录!  
process.pkl存放要爆破的进程(没它用不了,并且名称确定),编辑它,用我的pklTool.py.我暂时填的是"Taskmgr.exe".LindgeBreaker.ico是程序图标(没它会弹窗),打包exe时*必须*用这个图标.  
程序运行时会产生一个日志文件,报错就看这.  
授权文件,名称确定:auth.txt.实现嘛,自己看授权方法.    
为防止我的同学从这翻到授权码,程序下载后用授权文件使用.(sorry,有点麻烦,但我的同学,不得不防)

> ### EXE文件
> 直接运行,如果爆破不了就管理员运行.  
运行支持文件放在_internal文件夹,例如process.pkl  
呵呵,想用全套?我不给你!我把管理员模块从这里阉割了.
# 作者声明  
我必须***强调***,注意,是***强调!*** 本程序**不得在任何地方大规模使用,不得出现大规模的滥用管理员的行为,以及利用此程序进行商业行为!**.本程序使用MPL-2.0协议开源,按协议规定,你可以修改,传播本程序源代码,但修改后代码版权归软件发起人(我).
本程序官方名称:LindgeBreaker,可以简称LinB.管理员模块:LBAdmin,可以简称LBA.
# 其他  
有bug尽快提出来!!!我寒假和暑假在线,会改的(希望不要一上线,issue堆满了  
目前进入无限期停更,因为在干前端.
###### SJT 250123更
