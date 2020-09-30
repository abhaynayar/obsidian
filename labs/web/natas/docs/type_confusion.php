<?php

function blah($username) {
    strlen($username);
}

$username[] = "ASDF";

if(blah($username)) {
    echo "TRUE";
} else {
    echo "FALSE";
}

?>

