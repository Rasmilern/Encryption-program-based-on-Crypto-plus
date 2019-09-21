sub f(oExec)
Do While Not oExec.StdOut.AtEndOfStream
    cmdtext = oExec.StdOut.ReadAll()
Loop
msgbox cmdtext
end sub

Dim a,msg,p1,p2,cmdtext
msg = "输入选项:(输入0退出)" &vbcrlf& "    1.des加密;            2.des解密;" &vbcrlf&vbcrlf& "    3.生成摘要;           4.比较摘要;" &vbcrlf&vbcrlf& "    5.数字签名;           6.比较签名;" &vbcrlf&vbcrlf& "    7.数字信封;           8.拆开信封"

do

a=Inputbox(msg,"主菜单") 
if a=0 then exit do end if
if 0<a<9 then

Set r = CreateObject("WScript.Shell")
p1=inputbox("输入文件路径:","输入")
p2=inputbox("输出文件路径:","输出")

select case a
case 1  Set oExec = r.Exec("%COMSPEC% /C 后台程序.exe des1 "&p1&" "&p2)
	call f(oExec)
	r.run p2,1
	
case 2  Set oExec = r.Exec("%COMSPEC% /C 后台程序.exe des0 "&p1&" "&p2)
	call f(oExec)
	r.run p2,1
	
case 3  Set oExec = r.Exec("%COMSPEC% /C 后台程序.exe md5a "&p1&" "&p2)
	call f(oExec)
	r.run p2,1
	
case 4  Set oExec = r.Exec("%COMSPEC% /C 后台程序.exe md5b "&p1&" "&p2)
	call f(oExec)
	
case 5  Set oExec = r.Exec("%COMSPEC% /C 后台程序.exe sign1 "&p1&" "&p2)
	call f(oExec)
	r.run p2,1

case 6  Set oExec = r.Exec("%COMSPEC% /C 后台程序.exe sign0 "&p1&" "&p2)
	call f(oExec)
	r.run p2,1

case 7  Set oExec = r.Exec("%COMSPEC% /C 后台程序.exe alluse1 "&p1&" "&p2)
	call f(oExec)
	r.run p1,1

case 8  Set oExec = r.Exec("%COMSPEC% /C 后台程序.exe alluse0 "&p1&" "&p2)
	call f(oExec)
	r.run p1,1
end select

end if
loop while a



