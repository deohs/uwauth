<?php

namespace Drupal\uwauth;

use Drupal\Component\Utility\Unicode;

class Debug {

  protected $verbose;

  public function __construct($verbose = FALSE) {
    $this->verbose = $verbose;
  }

  /**
   * Display diagnostic information if enabled.
   *
   * @param string $message
   *   The message to display.
   * @param string $level
   *   The message severity level.
   */
  public function message($message, $level = 'status') {
    if (!$this->verbose) {
      return;
    }
    $stack = debug_backtrace(TRUE, 2);
    $caller = $stack[1];
    $class = empty($caller['class']) ? NULL : $caller['class'];
    $function = $caller['function'];
    if (!empty($class)) {
      $classArray = explode('\\', $class);
      $shortClassArray = [];
      $len = count($classArray);
      for ($i = 0; $i < $len - 1; $i++) {
        $shortClassArray[$i] = Unicode::substr($classArray[$i], 0, 1);
      }
      $shortClassArray[$len - 1] = $classArray[$len - 1];
      $shortClass = implode('\\', $shortClassArray);
    }
    else {
      $shortClass = '';
    }

    $message = ($shortClass ? "$shortClass::$function" : $function) . " $message";

    drupal_set_message($message, $level);
  }

}
