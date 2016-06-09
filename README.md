#**NOJ_JUDGE_CORE**

 
 - 之前写过一个完整的评测程序，内核引用的是[lorun](https://github.com/lodevil/Lo-runner)，本评测内核是作者一人完成，全新引擎，180匹马力...
 - 程序目标为运行用户程序，判断代码是否恶意，获取用户程序运行时间和内存，并且将输出重定向一个文件，具体比较data.out和user.out请自己写程序完成，这篇文章写的很好，可以参考[小码哥](http://ma6174.github.io/#show/2013-05-12-acmjudge)
 - 采用ptrace监控用户进程，限制系统调用和使用的动态库
 -  系统调用和动态库均采取白名单方式，由于环境不同因此引用时需要修改judge_client.h文件中的allow_so_file_white_list, 以运行一个 C写的helloword程序为例，具体这个进程用到的系统调用和动态库文件，可以通过strace ./helloword 来获取到
 - java jvm自带的安全策略，因此运行java用户程序时，ptrace一律放行
 -  目前定位为Python3的API python3 setup.py build_ext --inplace，使用时impore core即可
 -  参数传递，参见demo/con.py，切记传入都用str，如果是要运行java代码，第10个参数use_sandbox传入'0'即可
 - 内存计算略微偏大......但是在目前ACM题目的趋势看来，内存不算那么重要，这应该无伤大雅
 -  目前暂时没有对Stack Overflow 和 Access Violation做细的区分，均返回Runtime Error，但是对于Float Number Exception，比如Divide By Zero 则是做了提示的，另外恶意代码将会返回Malicious Code
 - 昨天测试发现被ptrace杀死的进程居然变成了僵尸进程，之后即刻修复...
 -  目前本程序只能运行在linux下，CentOS6.5 和 Ubuntu14.04均测试通过
 - ptrace效率存在一些问题，进程切换比较严重...
 -  程序还是有许多小问题，请各位不吝赐教
 - 感谢
	 -  http://ma6174.github.io/#show/2013-05-12-acmjudge
	 -  https://virusdefender.net/index.php/archives/652/
	 -  https://filippo.io/linux-syscall-table/
	 -  https://duguying.gitbooks.io/goj-book/content/zh/4/4.1.html
