# zlsafe
a php extension  function for the safe session and safe array for form (php7)
/*
* author:liang.zhang laowantong
* safe session will check the compute diff,if other compute or brower,will false,you can process it.
* safe form array,you can encrypt the form input or array key
*/
zlsafe add function  list

string zlsafe_session_id([ string $id ])
see session_id(),if set $id,the SESSIONID will set cookie and return sessionid,you can use it before session_start() 

string zlsafe_md5(string $id )
this function will return zlsafe_session_id sessionid,but not set cookie

string zlsafe_md5_real(string $str)
equal md5()

string zlsafe_md5_encrypt(string $str)
this function will encrypt for ip and brower infomation

bool zlsafe_session_check([ string $id ])
if not $id,zlsafe_session_check will return local sessionid check result,if sessionid not form this compute,it will return false

bool zlsafe_session_checkip([ string $id ])
if not $id,zlsafe_session_check will return local sessionid check result,if sessionid not form this compute ip,it will return false

array zlsafe_array_encrypt(array $data,string $key,[string $fun=encrypt|md5])
will encrypt all the key of array,please set $key for encrypt

array zlsafe_array_decrypt(array $data,string $key,[string $fun=decrypt])
will decrypt all the key of array,please set $key for decrypt

string zlsafe_encrypt(string $str)
the string will be encrypted,it  equal for zlsafe_array_encrypt key

string zlsafe_decrypt(string $str)
the string will be decrypted,it  equal for zlsafe_array_decrypt key
