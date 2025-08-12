<?php

function no_path_traversal_filter($page) {
  return  $page = str_replace('../', "", $page);
}

function handleRequest() {
    if (isset($_GET['page'])) {
        $page = $_GET['page'];

        
        if ($page === '/root/flag.txt') {
            echo "Access denied";
            return;
        }

        $pagePath = '/var/www/html/' . no_path_traversal_filter($page);

        if (file_exists($pagePath)) {
            include($pagePath);
        } else {
            echo "\nPage not found";
        }
    }
}


?>