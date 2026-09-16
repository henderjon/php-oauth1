<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';
require dirname(__DIR__) . '/harness/Config.php';

use BasicLti1\LaunchRequest;
use BasicLti1\LaunchRequestBuilderFactory;
use Harness\Config;
use Oauth1\Credentials;

session_start();

function renderLaunchForm( LaunchRequest $launch, string $note = '' ): void {
	echo '<!doctype html><html><head><title>Tool Consumer</title></head><body>';
	echo '<h1>Tool Consumer (simulated LMS)</h1>';
	if ( $note !== '' ) {
		echo '<p><strong>' . htmlspecialchars($note) . '</strong></p>';
	}
	echo '<p>This form carries a signed Basic LTI launch. View source to see every hidden field,';
	echo ' including the oauth_* ones LaunchRequestBuilder produced.</p>';
	echo '<form method="post" action="' . htmlspecialchars($launch->launchUrl) . '">';
	foreach ( $launch->parameters as $name => $value ) {
		echo '<input type="hidden" name="' . htmlspecialchars($name) . '" value="' . htmlspecialchars($value) . '">';
	}
	echo '<button type="submit">Continue to Tool Provider &rarr;</button>';
	echo '</form>';
	echo '<p><a href="?">&larr; Back</a></p>';
	echo '</body></html>';
}

$action = $_GET['action'] ?? 'home';

if ( $action === 'launch' ) {
	$credentials = new Credentials(Config::CONSUMER_KEY, Config::CONSUMER_SECRET);

	$launch = (new LaunchRequestBuilderFactory)->make()->build(Config::TOOL_PROVIDER_URL, $credentials, [
		'resource_link_id' => 'harness-resource-link-1',
		'context_id' => 'harness-course-1',
		'context_title' => 'php-oauth1 Example Course',
		'context_label' => 'EXAMPLE101',
		'user_id' => 'harness-user-1',
		'roles' => 'Instructor',
		'lis_person_name_full' => 'Ada Lovelace',
		'lis_person_contact_email_primary' => 'ada@example.test',
		'launch_presentation_return_url' => Config::TOOL_CONSUMER_URL,
	]);

	$_SESSION['last_launch_parameters'] = $launch->parameters;

	renderLaunchForm($launch);
	exit;
}

if ( $action === 'replay' ) {
	$parameters = $_SESSION['last_launch_parameters'] ?? null;
	if ( $parameters === null ) {
		echo 'No launch to replay yet - <a href="?action=launch">launch one first</a>.';
		exit;
	}

	renderLaunchForm(
		new LaunchRequest(Config::TOOL_PROVIDER_URL, $parameters),
		'Replaying the exact same signed request, byte for byte - the Tool Provider should reject this as a reused nonce.',
	);
	exit;
}

if ( $action === 'tamper' ) {
	$parameters = $_SESSION['last_launch_parameters'] ?? null;
	if ( $parameters === null ) {
		echo 'No launch to tamper with yet - <a href="?action=launch">launch one first</a>.';
		exit;
	}

	$parameters['roles'] = 'Administrator'; // changed after signing, without re-signing

	renderLaunchForm(
		new LaunchRequest(Config::TOOL_PROVIDER_URL, $parameters),
		'Changed "roles" to Administrator after signing, without re-signing - the Tool Provider should reject this as an invalid signature.',
	);
	exit;
}

echo '<!doctype html><html><head><title>Tool Consumer</title></head><body>';
echo '<h1>Tool Consumer (simulated LMS)</h1>';
echo '<p>A minimal Basic LTI 1.0 Tool Consumer, for exercising php-oauth1\'s BasicLti1 layer over real HTTP.</p>';
echo '<ul>';
echo '<li><a href="?action=launch">Launch</a> - build a fresh, correctly signed launch</li>';
echo '<li><a href="?action=replay">Replay last launch</a> - resend the exact same signed request</li>';
echo '<li><a href="?action=tamper">Tamper with last launch</a> - resend it with one value changed after signing</li>';
echo '</ul>';
echo '</body></html>';
