rule jjEncode {
    meta:
        author = "adnan.shukor@gmail.com"
        date = "2015-6-10"
        description = "jjencode detection"
        reference = "http://blog.xanda.org/2015/06/10/yara-rule-for-jjencode/"
    strings:
        $jjencode = /(\$|[\S]+)=~\[\]\;(\$|[\S]+)\=\{[\_]{3}\:[\+]{2}(\$|[\S]+)\,[\$]{4}\:\(\!\[\]\+["]{2}\)[\S]+/ fullword
    condition:
        $jjencode
}
