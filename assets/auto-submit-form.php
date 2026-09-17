<?php

declare(strict_types=1);

/**
 * A minimal auto-submitting HTML form - the mechanism Basic LTI's own examples use to deliver a
 * launch: the Tool Consumer POSTs a signed LaunchRequest to its launch URL, instead of a
 * 302-with-query-string GET, which would drop the oauth_* signature parameters a launch depends
 * on. This is the same mechanism as OIDC's response_mode=form_post - see php-oidc's own
 * assets/auto-submit-form.php, which this file is adapted from.
 *
 * Auto-submitting is JavaScript's job - there is no plain-HTML way to fire a POST with no user
 * interaction (a <meta http-equiv="refresh"> only ever issues a GET, losing the POST body a
 * launch depends on). The visible "Continue" button below is the fallback for a browser with
 * JavaScript disabled, not decoration - without it, that visitor would have no way to proceed
 * at all.
 *
 * This is a template, not a drop-in include - copy it into your own application and adapt the
 * escaping/templating to whatever it already uses. BasicLti1\LaunchRequest deliberately holds
 * data only, not markup (see its own docblock) - turning $launch->parameters into hidden form
 * fields is this template's job, not the library's. Variables expected in scope:
 *
 * @var \BasicLti1\LaunchRequest $launch       The signed launch to submit - $launch->launchUrl
 *                                              is the form action, $launch->parameters become
 *                                              hidden fields. Basic LTI launches are always
 *                                              POSTed, never GET.
 * @var string                   $message      Rendered above the form.
 * @var int                      $submitDelay  Seconds to wait before auto-submitting.
 * @var string                   $cspNonce     Nonce for the inline <script> below - required if
 *                                             your Content-Security-Policy uses
 *                                             'strict-dynamic' or a nonce source.
 * @var string|null              $target       Optional form target (e.g. to submit into a
 *                                              different window/frame).
 */

assert(isset($launch) && $launch instanceof \BasicLti1\LaunchRequest);
assert(isset($cspNonce) && is_string($cspNonce));
assert(!isset($target) || is_string($target));
assert(isset($submitDelay) && is_int($submitDelay) && $submitDelay >= 0);

function escape( string $value ): string {
	return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

echo escape($message);

?>
<form id="auto-submit-form"
	  method="POST"
	  action="<?= escape($launch->launchUrl) ?>"
	  <?php if( !empty($target) ) { ?>
		  target="<?= escape($target) ?>"
	  <?php } ?>>
	<?php foreach ($launch->parameters as $name => $value) { ?>
	<?php // (string) cast: a purely-numeric parameter name (e.g. a custom parameter literally
	// named "123") is stored as an int array key by PHP itself, and escape() rejects a
	// non-string argument under this file's own strict_types declaration. ?>
	<input type="hidden" name="<?= escape((string) $name) ?>" value="<?= escape($value) ?>" />
	<?php } ?>
	<input type="submit" value="Continue" />
</form>
<script nonce="<?= escape($cspNonce) ?>">
(function() {
	"use strict";
	setTimeout(function() {
		var form = document.getElementById("auto-submit-form");
		if (!form) {
			throw new Error("Could not get form");
		}
		form.submit();
	}, <?= (1000 * $submitDelay) + 50 ?>);
}());
</script>
<!-- Drop this noscript block immediately after the </form> tag above, and the browser submits as
     soon as it parses that line - it must not sit inside <noscript>, where it would render as
     visible page text rather than run as a comment. -->
<noscript>
<script>document.forms[0].submit();</script>
</noscript>
