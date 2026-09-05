<?php
// ruleid: cmdi-php-shell-funcs
shell_exec($_GET['cmd']);
// ruleid: cmdi-php-shell-funcs
system($_POST['cmd']);
// ruleid: cmdi-php-shell-funcs
passthru($_REQUEST['cmd']);
// ruleid: cmdi-php-shell-funcs
exec($_GET['cmd']);
// ok: cmdi-php-shell-funcs
exec(escapeshellcmd($safeCmd));
?>
