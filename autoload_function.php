<?php
return function ($className) {
    static $map;
    if (!$map) {
        $map = include __DIR__ . '/autoload_classmap.php';
    }

    if (!isset($map[$className])) {
        return false;
    }

    return include $map[$className];
};
