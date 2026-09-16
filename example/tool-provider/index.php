<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';
require dirname(__DIR__) . '/harness/Config.php';
require dirname(__DIR__) . '/harness/FileCache.php';

use BasicLti1\Exceptions\InvalidLaunchException;
use BasicLti1\LaunchVerifierFactory;
use Harness\Config;
use Harness\FileCache;
use Oauth1\Credentials;
use Oauth1\Exceptions\RequestVerificationException;

function page( string $body ): void {
	echo '<!doctype html><html><head><title>Tool Provider</title></head><body>';
	echo '<h1>Tool Provider (simulated Tool)</h1>';
	echo $body;
	echo '<p><a href="' . htmlspecialchars(Config::TOOL_CONSUMER_URL) . '">&larr; Back to Tool Consumer</a></p>';
	echo '</body></html>';
}

if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
	page('<p>This endpoint only accepts a signed Basic LTI launch POST. Start a launch from the Tool Consumer.</p>');
	exit;
}

$credentials = new Credentials(Config::CONSUMER_KEY, Config::CONSUMER_SECRET);
$nonceCache  = new FileCache(Config::NONCE_CACHE_FILE);

try {
	(new LaunchVerifierFactory)->make($nonceCache)->verify(Config::TOOL_PROVIDER_URL, $credentials, $_POST);
} catch ( RequestVerificationException $exception ) {
	page(
		'<p style="color:red"><strong>REJECTED - OAuth 1.0 verification failed</strong></p>'
		. '<p>Reason: ' . htmlspecialchars($exception->getReason()->name) . '</p>'
		. '<p>' . htmlspecialchars($exception->getMessage()) . '</p>',
	);
	exit;
} catch ( InvalidLaunchException $exception ) {
	page(
		'<p style="color:red"><strong>REJECTED - invalid Basic LTI launch</strong></p>'
		. '<p>Reason: ' . htmlspecialchars($exception->getReason()->name) . '</p>'
		. '<p>' . htmlspecialchars($exception->getMessage()) . '</p>',
	);
	exit;
}

$shown = [ 'resource_link_id', 'context_id', 'context_title', 'user_id', 'roles', 'lis_person_name_full', 'lis_person_contact_email_primary' ];

$rows = '';
foreach ( $shown as $name ) {
	if ( isset($_POST[$name]) ) {
		$rows .= '<tr><td>' . htmlspecialchars($name) . '</td><td>' . htmlspecialchars((string) $_POST[$name]) . '</td></tr>';
	}
}

page(
	'<p style="color:green"><strong>ACCEPTED</strong> - signature, nonce, timestamp, and Basic LTI parameters all checked out.</p>'
	. "<table border=\"1\" cellpadding=\"4\">$rows</table>",
);
