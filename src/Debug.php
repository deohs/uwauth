<?php

namespace Drupal\uwauth;

use Drupal\Core\Messenger\MessengerInterface;

/**
 * Class Debug provides configurable debug information.
 */
class Debug {

  /**
   * Debug flag.
   *
   * @var bool
   */
  protected bool $verbose;

  /**
   * The Messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected MessengerInterface $messenger;

  /**
   * Debug constructor.
   *
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param bool $verbose
   *   Display debug information?
   */
  public function __construct(MessengerInterface $messenger, bool $verbose = FALSE) {
    $this->messenger = $messenger;
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
  public function message(string $message, string $level = MessengerInterface::TYPE_STATUS): void {
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
        $shortClassArray[$i] = mb_substr($classArray[$i], 0, 1);
      }
      $shortClassArray[$len - 1] = $classArray[$len - 1];
      $shortClass = implode('\\', $shortClassArray);
    }
    else {
      $shortClass = '';
    }

    $message = ($shortClass ? "$shortClass::$function" : $function) . " $message";

    $this->messenger->addMessage($message, $level);
  }

}
